# 离线抓包接收台（Offline PCAP Receiving Station）

上传本地生成的 PCAP，在网页里按 **TCP 连接会话** 查看明文 HTTP/1.1 的请求、响应与
文件内容，并能从任意重组结果点回组成它的**具体报文**。只处理明文流量，**识别但绝不
解密 TLS**。

## 能力总览

- **会话拆分**：按五元组 demux；同一五元组再次连接（新 SYN）拆成独立会话实例。
- **TCP 重组引擎**（`app/core/reassembly.py`）
  - 32 位序号回绕：有符号模差 + 单调坐标，跨 2³² 边界正确拼接；
  - 乱序、完全重复、部分重叠；
  - 重叠字节相同 → 复用已有字节并登记双来源；
  - 重叠内容冲突 → 先到版本保留在主流，**冲突版本整段保留**并标注影响（头部/消息体/分块帧）；
  - 缺口永远是缺口：缺失字节不会被后续报文“补”成另一条消息。
- **HTTP/1.x 边界**（`app/core/http_parser.py`）：严格按 `Content-Length`、
  `Transfer-Encoding: chunked`、连接关闭定界；支持持续连接/流水线、gzip/deflate、
  无响应体（HEAD、1xx、204、304）、HTTP/1.0、obs-fold 与裸 LF 容错。
- **可视化样例**（`samples/`，由 `scripts/generate_samples.py` 生成 8 组）：
  基础、持续流水线、同五元组重连、乱序+重复、序号回绕、重叠冲突、中间缺口、gzip+分块。
- **三段长度对比**：网络原始长度（含重传）／重组内容／解压后文件。
- **导出**：JSON 报告与 ZIP（重组文件、原始 `.http`、`.gap` 缺口标记、冲突双方、清单），
  整体状态给出 `COMPLETE / GAPPED / CONFLICTS_PRESERVED`。
- 网页提供重组块/缺口/冲突色带、报文表格、十六进制载荷弹窗，无需另开抓包软件。

## 快速开始

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 生成可视化样例 PCAP
.venv/bin/python scripts/generate_samples.py

# 启动服务
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

浏览器打开 <http://127.0.0.1:8000/>，从左侧加载样例或上传 `.pcap/.pcapng/.cap`。

## 测试

```bash
.venv/bin/python -m pytest tests/ -q
```

48 个测试覆盖重组不变量（回绕/乱序/重复/冲突/缺口）、HTTP 定界与解压、端到端样例与导出。

## 目录结构

```
app/core/reassembly.py    TCP 序号映射、块重组、重叠冲突、缺口、溯源
app/core/stream_view.py   不跨缺口的读取窗口
app/core/http_parser.py   HTTP/1.x 消息定界、chunked、内容编码
app/core/analyzer.py      Scapy 读包、会话 demux、TLS 识别、请求/响应配对
app/core/serialization.py API JSON 负载
app/core/exporter.py      JSON / ZIP 导出（含 .gap 状态）
app/main.py               FastAPI 路由与静态前端
web/                      原生 JS 前端（无构建步骤）
scripts/                  样例 PCAP 合成工具
samples/                  生成的可视化样例
tests/                    pytest 单元与端到端测试
```

## 安全说明

上传文件写入临时目录后仅做离线解析，不执行其中任何内容；TLS 会话只做记录头识别并标记
`is_tls`，不会尝试解密。
