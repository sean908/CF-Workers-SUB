# CF-Workers-SUB 订阅聚合工具

CF-Workers-SUB 是一个基于 Cloudflare Workers 的代理订阅聚合工具，可以帮助您管理和聚合多个订阅源，支持多种客户端格式转换。

## 变动详细

### 代码结构

1. **模块化设计**：
   - 将代码重构为更小、更专注的函数，每个函数都有明确的职责
   - 添加了详细的注释和文档字符串，使代码更易于理解和维护

2. **配置管理改进**：
   - 引入了结构化的 `CONFIG` 对象，将相关配置分组
   - 配置项分为认证设置、Telegram 通知设置、订阅设置和 KV 命名空间设置

3. **代码可读性提升**：
   - 改进了变量命名，使其更具描述性
   - 统一了函数命名风格
   - 规范化了代码缩进和格式

### 功能增强

1. **认证系统**：
   - 优化了用户认证流程
   - 增强了凭证管理功能

2. **错误处理**：
   - 添加了更完善的错误处理机制
   - 增加了日志记录功能，便于调试

3. **订阅处理**：
   - 改进了订阅格式检测逻辑
   - 优化了订阅转换流程

4. **安全性提升**：
   - 增强了对环境变量的处理
   - 改进了密码存储和验证机制

## 部署指南

### 前提条件

- 一个 Cloudflare 账户
- 安装了 Node.js 和 npm
- 安装了 Wrangler CLI 工具

### 安装 Wrangler CLI

```bash
npm install -g wrangler
```

### 登录到 Cloudflare

```bash
wrangler login
```

### 部署方法一：直接部署

1. 创建一个新的 Worker

```bash
wrangler init my-subscription-worker
```

2. 将 `_worker_dev.js` 的内容复制到 `src/index.js`

3. 部署 Worker

```bash
wrangler publish
```

### 部署方法二：通过 Cloudflare Dashboard

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 进入 Workers & Pages
3. 创建一个新的 Worker
4. 将 `_worker_dev.js` 的内容粘贴到编辑器中
5. 点击 "Save and Deploy"

### 配置 KV 命名空间

1. 创建 KV 命名空间

```bash
wrangler kv:namespace create "KV"
```

2. 在 `wrangler.toml` 中添加 KV 绑定

```toml
kv_namespaces = [
  { binding = "KV", id = "your-namespace-id" }
]
```

或在 Cloudflare Dashboard 中：
1. 进入 Worker 设置
2. 点击 "Variables"
3. 在 "KV Namespace Bindings" 部分添加绑定
4. 绑定名称设为 "KV"，选择您创建的命名空间

### 环境变量配置

您可以通过环境变量自定义以下设置：

| 变量名 | 描述 | 默认值 |
|--------|------|--------|
| TOKEN | 主访问令牌 | auto |
| GUESTTOKEN | 访客令牌 | (自动生成) |
| USERNAME | 管理员用户名 | admin |
| PASSWORD | 管理员密码 | admin |
| AUTH_ENABLED | 是否启用认证 | true |
| TGTOKEN | Telegram 机器人令牌 | (空) |
| TGID | Telegram 聊天 ID | (空) |
| TG | Telegram 通知级别 | 0 |
| SUBNAME | 订阅名称 | CF-Workers-SUB |
| SUBUPTIME | 订阅更新时间(小时) | 6 |
| SUBAPI | 订阅转换后端 | SUBAPI.cmliussss.net |
| SUBCONFIG | 订阅转换配置文件 | (默认配置) |
| KV_NAMESPACE | KV 命名空间名称 | KV |

## 使用指南

### 访问订阅

1. 自适应订阅地址: `https://your-worker.workers.dev/TOKEN`
2. Base64 订阅地址: `https://your-worker.workers.dev/TOKEN?b64`
3. Clash 订阅地址: `https://your-worker.workers.dev/TOKEN?clash`
4. Singbox 订阅地址: `https://your-worker.workers.dev/TOKEN?sb`
5. Surge 订阅地址: `https://your-worker.workers.dev/TOKEN?surge`
6. Quantumult X 订阅地址: `https://your-worker.workers.dev/TOKEN?quanx`
7. Loon 订阅地址: `https://your-worker.workers.dev/TOKEN?loon`

### 管理订阅

1. 访问 `https://your-worker.workers.dev/TOKEN` (使用浏览器)
2. 使用管理员凭证登录
3. 在编辑器中添加或修改订阅链接和节点
4. 点击保存

## 注意事项

1. 首次使用时请修改默认的管理员用户名和密码
2. 为了安全起见，建议修改默认的访问令牌
3. 如果启用 Telegram 通知，请确保正确配置 TGTOKEN 和 TGID


## 致谢

本项目基于 [cmliu/CF-Workers-SUB](https://github.com/cmliu/CF-Workers-SUB) 进行优化和改进。
