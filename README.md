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

## 离线 Merkle 证明（只读）

`GET /streams/{id}/records/{seq}/proof?watermark=N` 供离线审查方独立确认
某条已封存记录确实属于指定历史前缀，无需下载整段记录。它**绝不开启写
事务**，不改变水位、冻结裁决或任何已有的重传裁决。

- 只对已 `sealed` 的序号、且 `1 <= N <= 当前水位` 提供证明；pending
  记录永远无法进入证明。冻结流只能在它停住的水位取已有前缀，
  `watermark` 越界（0、负数、超过当前水位）一律拒绝。
- 叶节点的待哈希数据按固定二进制顺序编码，**不经过 JSON 重编码**：

  ```
  u16be(len(id)) || id 的 ASCII 字节 || u64be(seq)
  || prev_digest[32] || payload_digest[32] || signature[64]
  ```

- 哈希带域标签，叶与内部节点不可互混：

  ```
  leaf = sha256(0x00 || leaf_pre_image)
  node = sha256(0x01 || left || right)
  ```

  奇数层的尾节点**原样提升**（不复制、不重新哈希）；单叶树的根即叶摘要。
- 响应自包含：完整记录字段、前缀根摘要，以及**叶到根**顺序的兄弟摘要
  数组；每项的 `position`（`left`/`right`）标明兄弟相对被证节点的位置，
  审查方仅凭响应即可复算根。历史水位在后续补齐记录、发生重传或服务重启
  后给出完全相同的根与路径。
- 错误码：流不存在 404；序号不在该前缀（含 0、含 pending）404；
  `watermark` 为 0/负数/非整数 422；超过当前水位 404。

响应示例：

```json
{
  "id": "buoy-001",
  "seq": 2,
  "watermark": 3,
  "record": {
    "prev_digest": "…",
    "payload_digest": "…",
    "signature": "…"
  },
  "root_digest": "…",
  "proof": [
    {"digest": "…", "position": "right"},
    {"digest": "…", "position": "left"}
  ]
}
```


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
   并发同内容/冲突内容提交；
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
app/merkle.py    固定二进制叶编码、域标签哈希、奇数层提升与 Merkle 路径
app/storage.py   SQLite 模式、事务化提交、封存循环、分叉冻结、重启重建、只读证明
app/main.py      FastAPI 路由与 Ed25519 原始消息验签
tests/           行为测试（含独立复算的 Merkle 证明测试）
scripts/         smoke.py / verify.sh / verify-all.sh
```
