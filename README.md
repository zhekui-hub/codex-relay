# Codex Relay 服务器部署记录

这是经过脱敏的服务器端中转源码。真实主机名、用户名、上游域名和地区信息已替换为示例值；`upstream-a.invalid` 和 `upstream-b.invalid` 不会解析。仓库包含面向 Linux 用户级 systemd 的交互式安装器，已在隔离的 Ubuntu 24.04 systemd 容器中以虚构 Key 和本地 TLS 上游验证；其他发行版和真实上游仍需自行验证。

## 安装

在目标 Linux 服务器，以专门运行中转的普通用户执行，不要使用 `sudo` 或 root 运行安装器。需预先安装 Python 3.10+、Nginx（支持 HTTPS 代理）、curl、flock、ss 和 systemd 用户服务，并确保 `/etc/ssl/certs/ca-certificates.crt` 存在、`systemctl --user show-environment` 成功。安装器不会安装系统依赖或配置登录后持久运行；需要时由管理员单独确认用户服务的登录会话和 linger 设置。

取得此仓库后，在仓库目录执行：

```bash
python3 install.py
```

按提示输入上游 HTTPS 地址（不带 `/v1`）和自己的 API Key。Key 输入不回显；安装器先通过上游 `/v1/models` 验证 Key，再写入该用户的私有目录，创建并启用用户级服务。已存在同名目录或服务、端口占用、依赖缺失或上游验证失败时会停止；不覆盖现有安装。服务器需能直接访问上游并验证其证书。安装成功的标志是 `/v1/models` 验证通过。

通过 SSH 访问时，在客户端以能够登录目标服务器的普通用户执行以下示例；先把 `user@server` 换成自己的 SSH 目标：

```bash
ssh -N -L 127.0.0.1:18081:127.0.0.1:18080 user@server
```

在另一个本机终端执行 `curl --fail http://127.0.0.1:18081/healthz` 应返回 `ok`；模型客户端的 API base URL 使用 `http://127.0.0.1:18081/v1`。共享入口 `/v1/` 使用独立生成的本机访问令牌，未经认证返回 401，避免其他普通用户直接使用服务器 Key；服务器 root 和同一用户仍可读取该令牌。`healthz` 仅证明隧道和 Nginx 可达。

在客户端以普通用户执行以下示例；先确认 `user@server` 是目标服务器，并确保本机目标文件不存在。命令通过 SSH 创建仅当前用户可读的认证头文件，不输出令牌：

```bash
umask 077
mkdir -p "$HOME/.config/codex-relay"
(set -C; ssh user@server 'cat ~/.local/share/codex-relay/nginx/local-client.header' > "$HOME/.config/codex-relay/local-client.header")
curl --fail --silent --show-error --header "@$HOME/.config/codex-relay/local-client.header" http://127.0.0.1:18081/v1/models
```

该文件包含 `Authorization: Bearer` 和访问令牌，不是上游 API Key；不要分享、提交或打印。设置模型客户端使用该令牌作为 API Key，并验证 `/v1/models` 返回 HTTP 200。上游不支持 `/v1/models` 或响应 3xx 时安装会失败。安装器目前只支持 HTTPS 标准端口 443。

如果安装失败，安装器会尝试停止本次创建的用户级服务，并保留私有文件供排查，不自动删除。以同一普通用户检查 `systemctl --user status codex-relay-nginx.service` 及 `~/.local/share/codex-relay/nginx/logs/error.log`；检查文件前注意日志可能包含敏感信息。确认服务已停止且这些目录与 `~/.config/systemd/user/codex-relay-*` 全部属于本次安装后，才能手工删除并运行 `systemctl --user daemon-reload`；保留需要的备份。不要删除其他用户或既有服务文件。

## 工作方式

```text
Codex 客户端 -> 本机 127.0.0.1:18081 -> SSH 本地端口转发
    -> 服务器 127.0.0.1:18080 -> Nginx -> HTTPS 上游 API
```

部分本机配置还会在 18081 前增加 127.0.0.1:18082 模型路由层；它不属于此服务器快照。SSH 客户端、桌面 App 与本机配置也未包含在此仓库。

服务器 Nginx 的两个入口行为不同：

- `/v1/`：加载 `nginx/upstream-auth.conf`，使用服务器当前选中的路由及其 API Key。
- `/client/v1/`：使用客户端传来的 `Authorization`，由 Nginx 转发给配置的上游。
- `/healthz`：仅检查本机 Nginx 是否响应，不代表上游 Key 或模型调用可用。

访问日志配置只记录时间、方法、路径、路由名、状态和耗时等元数据，不记录正文或 Authorization；但 Nginx、服务器管理员和上游服务在处理请求时仍具备读取请求内容的能力。不要把这种代理理解为端到端加密。客户端持有的本机访问令牌和服务器 Key 是两种不同凭据；安装器会将两者保存在服务器私有目录中。

**上游证书校验风险**：参考快照中的 `/client/v1/` 显式设置了 `proxy_ssl_verify on`；共享 `/v1/` 的主配置和路由生成脚本未设置。已检查的原运行配置也没有显式设置；Nginx 的 [proxy_ssl_verify 默认值为 off](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify)，因此原共享入口可能未校验上游证书，存在中间人冒充上游、截取 Key 和请求内容的风险。安装器为新安装的共享入口显式开启校验，不会修改已有服务。完整生效配置仍需在原服务器上安全核实。

## 仓库内容

| 路径 | 作用 |
| --- | --- |
| `install.py` | 检查依赖、交互式验证 Key、生成配置并安装用户级服务。 |
| `nginx/nginx.conf` | Nginx 主配置，监听服务器回环地址及两个 API 入口。 |
| `server/route-lib.sh` | 路由校验和动态 Nginx 上游配置生成。 |
| `server/probe-upstream-keys.sh` | 探测候选 Key，生成健康路由池并处理隔离状态。 |
| `server/rotate-upstream-auth.sh` | 轮转健康路由，reload 失败时恢复先前认证配置。 |
| `server/quarantine-current-key.sh` | 将失败路由隔离并尝试切换。 |
| `server/codex-relay-key-failure-monitor.sh` | 根据共享入口的访问日志监视失败。 |
| `server/dashboard_remote.py` | 管理端的状态查询及受限路由操作。 |
| `systemd/` | Nginx、探针、轮转、失败监控的用户级 service 和 timer。 |

## 原机器上的配置

服务目录为 `~/.local/share/codex-relay/`，systemd 单元位于 `~/.config/systemd/user/`，使用普通用户的 `systemctl --user` 管理，不是系统级 Nginx 服务。单元和 Nginx 配置中的 `/home/relay-user/` 是示例路径；部署前需核对账户、路径、上游地址及相关白名单。

按当前快照，探针 timer 在每天 08:00–21:59 每分钟执行，轮转 timer 在每小时整点和半点执行；具体时间以服务器 systemd 的时区为准。路由操作使用锁协调，并将路由文件和临时文件限制为私有权限。管理脚本和探针依赖 Bash、Python 3、curl、flock、systemd 用户服务、可用的 Nginx 和对应证书链。

隔离路由恢复探针在满足脚本条件时，会向上游发送真实模型请求，可能消耗 Key 的额度；一般 `/v1/models` 探针与此不同。

该仓库**不包含** Nginx 二进制、SSH 密钥、API Key、`upstream-auth.conf`、候选/活动 Key 池、隔离和禁用状态、运行日志或备份。安装器生成运行所需的初始路由；管理脚本本身不包含空池 `bootstrap` 实现。安装器当前只配置一个上游地址，恢复隔离路由的业务探针使用源码中配置的模型名；该模型不可用时可能无法自动恢复。

## 检查已部署实例

在目标服务器以部署该服务的普通用户执行；先确认登录的是目标机器。以下命令只读取状态，不启动或修改服务：

```bash
systemctl --user is-active codex-relay-nginx.service \
  codex-relay-key-probe.timer codex-relay-key-rotate.timer \
  codex-relay-key-failure-monitor.service
ss -ltn | grep -F '127.0.0.1:18080'
curl --fail --silent --show-error --max-time 10 http://127.0.0.1:18080/healthz
```

正常情况下，四个单元显示 `active`，监听地址仅为 `127.0.0.1:18080`，健康检查返回 `ok`。若单元不 active，检查普通用户的 `systemctl --user status <unit>`；若监听或健康检查失败，检查该用户的服务状态与网络，不要直接重启生产服务。

## 迁移、备份与回滚

部署前应核对 Nginx 版本、systemd 用户会话、证书、端口占用、上游权限、脚本允许的域名、凭据注入方式、文件权限、定时器和回滚方案；不要把现有机器的私密运行文件提交到 GitHub。涉及正在使用的服务，先得到管理员对目标、停机窗口和回滚的确认。

迁移时在目标普通用户的私有目录中分别准备受保护的 Key 池和认证 include，真实凭据通过安全渠道提供；不要放入命令行、仓库、日志或截图。变更前保存私有备份并确认其权限。出现故障时，按已确认的部署方案恢复备份和用户级单元，再验证回环监听、健康检查和经过授权的实际 API 请求。不要将历史迁移文档中清理审计或系统日志的建议作为部署步骤。

路由管理操作失败时，如果受管理文件在写入后又发生变化，程序会报告 `managed state changed after write, rollback skipped`，保留当前状态和备份以避免覆盖其他更新。本次探针自身或并发操作都可能触发这种情况，不能据此断定发生了并发。管理员应先停止新的管理操作，核对状态、备份和服务，再决定是否恢复；不能假定操作已经自动回滚。

仓库私有不等于绝对安全：授予访问权限的 GitHub 用户和平台可访问仓库内容。发布前检查仓库可见性和协作者权限；如需要公开，请先完成进一步审查和授权。暂未指定开源许可证，因此私有保存不自动授予开源许可。
