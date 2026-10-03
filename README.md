# Buoy Signed-Prefix Archive

深海浮标测量摘要的岸站封存服务。它从乱序、重传、进程中断与并发提交中，
**只封存一条连续且未分叉的采集前缀**；一旦检测到分叉，该流被原子冻结，
前缀永不继续推进。

## 规则

- `POST /streams` 登记 ASCII 标识与 Ed25519 公钥（32 字节原始密钥，base64）。
  同一标识再次登记：公钥相同则幂等成功；**公钥不同返回 409，密钥不可更换**。
- `POST /streams/{id}/records` 提交 `seq`（从 1 开始）、`prev_digest`（32 字节）、
  `payload_digest`（32 字节）、`signature`（64 字节 Ed25519，base64）。
- 验签只针对规定的二进制消息，绝不重新编码 JSON：

  ```
  u16be(len(id)) || id 的 ASCII 字节 || u64be(seq) || prev_digest[32] || payload_digest[32]
  ```

  首条记录的 `prev_digest` 必须是 32 字节全零。
- 距当前连续水位不超过 **32** 的乱序记录先保持 `pending`；缺口补齐后在
  同一次提交里按序封存（`sealed`）。
- 同序号且内容/签名完全相同的重传：返回**该记录上一次的裁决**
  （`duplicate: true`）。
- 同序号但内容或签名不同，或待封存时 `prev_digest` 与当前尾摘要不匹配：
  **在同一个 SQLite 事务内**把流冻结为 `forked`，水位停在分叉点，之后不再推进。
- 记录、水位与冻结裁决的写入在同一个 `BEGIN IMMEDIATE` 事务中完成，响应只在
  提交后返回；进程内加锁串行化，因此并发提交不会重复封存或出现短暂错误成功。
- 重启时打开数据库会**从已封存记录重放重建**水位与尾摘要，pending 记录保留，
  重传裁决与重启前完全一致。
- `GET /streams/{id}/records/{seq}/proof?watermark=M` 返回已封存记录在某历史
  水位 `M`（`1 ≤ M ≤ 当前水位`）下的 **Merkle 包含证明**：记录本体、前缀根摘要、
  以及按叶到根顺序给出的兄弟摘要与左右位置。该查询为纯只读，不改变水位、
  冻结裁决或重传结果；pending / forked 记录绝不进入证明；冻结流只按其停住的
  水位提供已有前缀。

## Merkle 证明编码（固定规则，可独立复算）

树覆盖且仅覆盖已封存记录 `1..M`，`seq = s` 的记录位于 0 基叶下标 `s - 1`。
所有编码均为固定二进制顺序，绝不重新编码 JSON：

```
叶摘要   = SHA-256( 0x00 || u16be(len(id)) || id 的 ASCII 字节
                    || u64be(seq) || prev_digest[32]
                    || payload_digest[32] || signature[64] )
内部节点 = SHA-256( 0x01 || left[32] || right[32] )
```

奇数层的落单节点**原样提升**到上一层（不复制、不重哈希）；单叶树的根即叶摘要
本身，路径为空。审查方仅凭响应即可重建根：用响应中的记录字段与 `id`、`seq`
重算叶摘要，再按 `leaf_index` / `leaf_count`（即水位）推出提升层，沿 `path`
逐项折叠（`position: "left"` 表示兄弟在左，`"right"` 表示兄弟在右），最终值
必须等于 `root_digest`。已封存记录不可变，因此历史水位的根与路径在后续补齐、
重传或服务重启后保持不变。

## 响应示例

```json
{
  "id": "buoy-001",
  "seq": 2,
  "state": "sealed",          // sealed | pending | forked
  "status": "active",         // active | forked
  "watermark": 2,
  "tail_digest": "…",         // 32 字节，hex
  "duplicate": false
}
```

`forked` 裁决使用 HTTP 409；签名不合法 403；缺口超过 32 返回 422；
未登记的流返回 404。

证明查询的响应示例（`GET /streams/buoy-001/records/2/proof?watermark=5`）：

```json
{
  "id": "buoy-001",
  "seq": 2,
  "state": "sealed",
  "status": "active",
  "watermark": 5,
  "current_watermark": 9,
  "record": {
    "seq": 2,
    "prev_digest": "…",         // base64，与提交时一致
    "payload_digest": "…",
    "signature": "…"
  },
  "leaf_index": 1,
  "leaf_count": 5,
  "leaf_digest": "…",           // 32 字节，hex
  "root_digest": "…",           // 前缀根摘要，hex
  "path": [
    {"digest": "…", "position": "left"},
    {"digest": "…", "position": "right"}
  ]
}
```

证明查询的拒绝：未登记的流 404；序号未封存（pending / forked / 不存在）404；
水位为零、为负或超过当前水位（冻结流即停住的水位）422；序号已封存但超出
所请求水位覆盖范围 422。

## 运行

宿主机端口可用 `HOST_PORT` 配置（默认 8080）：

```bash
HOST_PORT=9090 docker compose up -d app
curl -s http://localhost:9090/health
```

数据库保存在命名卷 `buoy-data`（容器内 `/data/buoy.db`，SQLite WAL）。

## 验证（测试 + 镜像构建检查 + HTTP 冒烟）

一键完成：构建两个镜像 → 启动 app → 运行一次性的 `verify` 容器，
完成后退出并用退出码报告结果：

```bash
./scripts/verify-all.sh
```

或分步：

```bash
docker compose build                         # 镜像构建检查
docker compose run --rm verify               # 代码测试 + HTTP 冒烟
```

`verify` 容器（`scripts/verify.sh`）依次执行：

1. 构建产物自检：`import app.main`（镜像构建阶段已执行一次）；
2. `pytest`：乱序归并、缺口内/外边界、篡改签名、首条全零前序、
   待封存 prev 不匹配冻结、冲突重传冻结、重启水位重建与裁决保持、
   并发同内容/冲突内容提交、Merkle 证明的独立复算/错误边界/只读性；
3. `scripts/smoke.py`：对运行中的 app 容器做真实 HTTP 冒烟。

### 无 Docker 环境下本地运行测试

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-test.txt
PYTHONPATH=. python -m pytest
```

## 布局

```
app/message.py   规定二进制消息的编码
app/merkle.py    叶/内部节点的固定二进制编码、根与 Merkle 路径的生成和复算
app/storage.py   SQLite 模式、事务化提交、封存循环、分叉冻结、重启重建、证明读取
app/main.py      FastAPI 路由与 Ed25519 原始消息验签
tests/           行为测试
scripts/         smoke.py / verify.sh / verify-all.sh
```
