# 西南林业大学教务助手插件（统一身份认证 + 校历作息）

[教务助手](https://github.com/znjhahaha/zhengfang-apk) 的学校适配插件，API v3 / SDK 3.11.1。
学校教务改用统一身份认证后，本插件接管登录，并用学校「按周次课表」接口提供准确的节次时间与开学日期；
学期、课表、成绩、考试与选课继续复用内置新正方协议。

- 插件 ID：`cn.edu.swfu.academic`
- 类型：`extension`，`extends: builtin.zf`
- 版本：1.1.1
- 许可证：GPL-3.0-only
- 适配学校：西南林业大学（`jw.swfu.edu.cn`，统一认证 `cas.swfu.edu.cn`）

## 功能

1. **统一认证登录**：App 内输入学号 + 个人门户密码，按学校 `security.js` 规格用
   「密码倒序 + 教科书式 RSA（无 PKCS#1 填充）」加密后提交 CAS；支持图片验证码与刷新。
2. **网页登录交接**：遇到短信/动态码二次认证或页面异常时，转官方 CAS 页面登录，回来再核验身份。
3. **身份核验**：资料页只有姓名（`.media-heading`），学号取自首页 `#sessionUserKey`；缺学号时回退登录账号。
4. **校历作息**：`study.calendar` 按学期返回开学日期与 12 节次真实起止时间
   （1 节 08:20–09:05、3 节 10:25–11:10 等），修正 App 默认节次时间；接口异常时降级，不影响课表。
5. **风控保护（1.1.1）**：CAS 返回 HTTP 423（账号被临时锁定，约 30 分钟自动解锁）时，
   返回「需要人工登录」而不是可重试错误，避免宿主自动续登在锁定期内反复提交登录。

## 数据来源（2026-11-13 实测）

| 用途 | 接口 |
| --- | --- |
| 登录入口 | `/jwglxt/xtgl/login_slogin.html` → `/sso/zfiotlogin` → `https://cas.swfu.edu.cn/cas/login?service=…` |
| 公钥 / 验证码 | `POST /cas/v1/getPubKey`、`GET /cas/getKaptchaStatus`、`GET /cas/kaptcha` |
| 学期周次与开学日期 | `POST /jwglxt/kbcx/xskbcxZccx_cxZcByXnxq.html`（`xnm`,`xqm`）→ `[{zs,zcrq}]` |
| 节次时间 | `POST /jwglxt/jzgl/skxxMobile_cxRsdjc.html`（`xnm`,`xqm`,`xqh_id`）→ `[{jcmc,qssj,jssj}]` |
| 校区号 | `POST /jwglxt/kbcx/xskbcxMobile_cxXsKb.html`（`kblx=2`）的 `kbList[].xqh_id` |

- 2026-2027-1：第 1 周 2026-08-31～09-06，共 20 周；
- 12 节次：1 节 08:20–09:05、2 节 09:10–09:55、3 节 10:25–11:10、4 节 11:15–12:00、
  5 节 14:00–14:45、6 节 14:50–15:35 等。

## 安装

1. 下载 `dist/cn.edu.swfu.academic-1.1.1.eduplugin`；
2. App「插件中心 → 右上角更多 → 导入、回滚与开发工具」，下滑开启 **开发者模式**；
3. 「导入适配包」选择该文件；
4. 提示「已验证并暂存」后，到「插件中心 → 已安装」应用该版本；
5. 登录页选择「西南林业大学」，输入学号与个人门户密码，在课表页下拉刷新。

> App 只在用户没有手动改过节次时间时才采用插件作息；若之前手动改过「课表设置 → 节次时间」，
> 需要恢复默认后才会生效。

## 验证范围

- 真实登录链路、课表接口、周次与节次接口均已实测（2026-11-13）。
- 离线 18 条样本全部通过：认证全入口、CAS 退回重试、验证码、账号密码错误、423 风控锁定转人工登录、
  二次认证网页交接、网页登录后核验、身份回退、会话失效、过期续接、作息正常/空周次/接口异常回退。
- **未验证**：Android 真机上登录后的课表节次时间显示、学期切换、成绩/考试与选退课；
  学期课表与 20 个单周课表并集的完整性对比。
- **已知限制**：手动节次时间优先于插件作息；实践课（`sjkList`）不显示；调课/停课不按临时日期调整；
  学校风控锁定约 30 分钟自动解锁。

## 构建

使用官方开发套件 `plugin-starter-v3.zip`（SDK 3.11.1）。解压后把本仓库内容放到 `plugins/swfu-sso/`
（`manifest.json`、`src/`、`fixtures/`、`LICENSE`；`dist/` 可忽略），在非 `/sdcard` 的文件系统下运行：

```sh
npm ci
npm run plugin -- doctor
npm run plugin -- check swfu-sso
npm run plugin -- test swfu-sso
npm run plugin -- submit-check swfu-sso
npm run plugin -- pack swfu-sso
npm run plugin -- source-zip swfu-sso
```

产物：`dist/cn.edu.swfu.academic-<version>.eduplugin` 与 `-source.zip`。

## 目录

```
manifest.json      插件清单（ID、能力、网络白名单、学校匹配、验证范围）
src/index.ts       认证与校历作息实现
fixtures/cases.json 合成样本（不含真实账号与学生数据）
dist/              构建产物：安装包与源码 ZIP
LICENSE            GPL-3.0-only
```

## 声明

社区维护的第三方插件，与西南林业大学及正方软件无隶属关系。源码与样本中不含账号、密码、Cookie、
真实学号或学生数据。参考了同生态已发布插件（`cn.edu.swcvc.academic`、`local.zhongbei-sso`、
`cn.edu.ycit.academic`）的扩展结构与错误处理约定，实现按本校实际响应重写。
