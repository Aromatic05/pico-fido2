# Aromatic Key 使用说明书

Aromatic Key 是基于 ESP32-S3 的多协议硬件安全密钥。设备在日常模式下可作为 FIDO2 / U2F / WebAuthn 安全密钥、OTP 设备以及 CCID 智能卡使用，并提供 PIV、OpenPGP、OATH 与 YubiHSM Auth 兼容能力。

本文面向设备使用者。固件编译、eFuse provisioning、签名密钥与开发调试流程不属于日常使用范围。

## 1. 快速开始

1. 将 Aromatic Key 插入电脑 USB 端口。
2. 等待 LED 进入**蓝色常亮**。这表示设备已经正常挂载并处于空闲状态。
3. 在网站或应用要求安全密钥确认时，等待 LED **黄色闪烁**。
4. 黄色闪烁期间，短按一次 **BOOT**。
5. 设备接受本次物理确认后会**白色双闪**，随后继续处理请求并回到蓝色常亮。

不要在没有黄色提示时为了“确认”而反复按 BOOT。BOOT 同时承担 OTP 按键与维护模式入口等物理交互职责。

## 2. LED 状态说明

Aromatic Key 的 LED 不是单纯的活动灯，而是设备状态机的直接反馈。

| LED | 含义 | 应做什么 |
| --- | --- | --- |
| **蓝色常亮** | 正常、USB 已挂载、设备空闲 | 正常使用 |
| **蓝色慢闪** | USB 总线进入 suspend | 一般无需处理；主机恢复 USB 后会回到正常状态 |
| **青色快闪** | 正在处理协议命令 | 等待操作完成 |
| **黄色闪烁** | 正在等待物理触摸 / User Presence | 短按一次 BOOT |
| **白色双闪** | 本次物理触摸已被设备接受 | 无需再次按键 |
| **绿色常亮** | Wi-Fi Maintenance / 管理模式 | 可连接管理 Wi-Fi 并打开管理面板 |
| **红色慢闪** | 启动中、USB 尚未正常挂载或设备尚未 ready | 等待设备完成启动；长时间不恢复则重新插拔 |
| **红色快闪** | 错误状态 | 停止当前操作；若不能自动恢复，重新插拔并检查设备 |

典型 FIDO / WebAuthn 操作的灯光顺序为：

```text
蓝色常亮
→ 青色处理
→ 黄色等待触摸
→ 白色双闪
→ 青色处理
→ 蓝色常亮
```

部分操作很快，青色阶段可能只短暂出现。黄色状态会持续等待用户确认，不需要抢时间按键。

## 3. FIDO2 / U2F / WebAuthn

Aromatic Key 可作为标准 USB 安全密钥用于网站登录、Passkey / WebAuthn 注册与二次认证。

### 注册新的安全密钥

1. 在网站或操作系统中选择“添加安全密钥”“Security Key”或类似入口。
2. 选择 USB 安全密钥。
3. 当 Aromatic Key LED 开始黄色闪烁时，短按一次 BOOT。
4. 看到白色双闪后，设备已经接受本次物理确认。
5. 等待网站完成注册。

### 使用安全密钥登录

流程与注册相同：在黄色闪烁时按一次 BOOT。Aromatic Key 不会在未获得所需物理确认时静默通过 User Presence 检查。

如系统要求 FIDO PIN，请使用系统、浏览器或兼容 FIDO 管理工具完成 PIN 操作。

## 4. OTP

Aromatic Key 提供 YubiKey 风格 OTP / challenge-response 兼容能力，并可通过 USB HID 键盘接口输出 OTP。

BOOT 按键还承担 OTP 的物理操作。维护模式使用的是**连续短按 5 次 BOOT**，与正常的 1–4 次 OTP 按键序列分开。

如果只是进行 FIDO / WebAuthn 触摸确认，应只在 LED 黄色闪烁时短按一次 BOOT。

## 5. CCID 智能卡功能

Aromatic Key 通过 USB CCID 暴露多种智能卡应用。

### PIV

可使用 `ykman` 等兼容工具管理 PIV：

```bash
ykman piv info
```

PIV 提供认证、签名、密钥与证书槽等标准能力。

### OpenPGP

可使用 GnuPG：

```bash
gpg --card-status
```

支持 OpenPGP Card 3.4 兼容工作流，包括签名、加密和认证密钥槽。

### OATH

支持 YKOATH 兼容的 TOTP / HOTP 凭据，可使用兼容的 YubiKey / OATH 工具进行管理。

### YubiHSM Auth

支持 YubiHSM Auth 兼容凭据，可通过兼容的 `ykman hsmauth` / yubikit 工作流使用。

这些应用的私钥、种子和凭据不会通过 Wi-Fi 管理页面读取或导出。

## 6. 常用状态检查

Linux 下可用以下命令快速确认设备：

```bash
ykman list
fido2-token -L
ykman piv info
gpg --card-status
```

正常生产设备会以 YubiKey 兼容 USB 组合设备出现，并同时提供 OTP、FIDO HID 和 CCID 接口。

## 7. 进入管理模式

Aromatic Key 日常启动时不会开放 Wi-Fi 管理页面。管理模式必须由本机物理按键开启。

### 进入步骤

1. 保持 Aromatic Key 正常插在电脑上，确认 LED 为蓝色常亮。
2. **连续短按 BOOT 5 次。**
3. 等待 LED 变为**绿色常亮**。
4. 在电脑或手机的 Wi-Fi 列表中找到：

```text
PicoFIDO2-XXXX
```

其中 `XXXX` 是设备标识的一部分。

5. 使用 Aromatic Key 的固定 WPA2 维护密码连接：

```text
PicoFIDO2-39eca8a6e423
```

该密码是当前 Aromatic Key v1.0.0 production profile 的共享维护密码，所有使用同一 production 配置构建的设备相同。它不是设备私钥，也不是用于保护 FIDO / PIV / OpenPGP / OATH 凭据的密钥。共享密码只负责维护 SoftAP 的无线链路访问控制；设备仍必须先在本机连续短按 BOOT 5 次，才会实际开放 Maintenance 会话。
6. 打开浏览器访问：

```text
http://192.168.4.1
```

管理模式只允许一个 Wi-Fi 客户端连接，并要求 WPA2 / PMF。设备进入管理模式后会暂停正常 BLE 工作。

### 修改生产 Wi-Fi 密码

当前仓库的 production 构建通过一个外部文本文件注入维护密码。当前本机使用的文件是：

```text
var/production-wifi-password.txt
```

文件当前内容为：

```text
PicoFIDO2-39eca8a6e423
```

要修改以后构建出的 Aromatic Key 的维护密码，直接修改该文件，例如：

```bash
printf '%s\n' 'New-Aromatic-Key-Password' > var/production-wifi-password.txt
chmod 600 var/production-wifi-password.txt
```

production 构建脚本通过环境变量 `PICO_FIDO2_WIFI_PASSWORD_FILE` 指向这个文件：

```bash
export PICO_FIDO2_WIFI_PASSWORD_FILE=var/production-wifi-password.txt
```

实际读取和注入逻辑位于：

```text
tools/esp32s3_maintenance_profile.sh
```

production profile 会把文件内容写入构建期配置项：

```text
CONFIG_PICO_FIDO2_WIFI_PASSWORD
```

`src/fido2/Kconfig` 中的默认值 `pico-fido2` 不是 Aromatic Key 当前 production 密码；production 构建会用上述文件中的值覆盖它。

例如重新构建 production A/B OTA 固件：

```bash
source ../esp-idf-v5.5/export.sh
PICO_FIDO2_WIFI_PASSWORD_FILE=var/production-wifi-password.txt \
  ./tools/build_esp32s3_ab_ota_update_bundle.sh \
  baseline/physical-2884856dbe88-secure/provisioning \
  build-ab-ota-production \
  7.4.104 0 production
```

修改密码只影响**之后重新构建的固件**。已经烧录在设备中的密码不会因为修改本机文本文件而变化；必须重新构建签名 production 固件并通过 OTA 安装到设备，新的密码才会生效。

### 自动退出

管理会话在**连续 10 分钟无活动**后自动重启设备并退出 Wi-Fi Maintenance。

也可以在管理面板中直接点击 **Restart device** 主动退出。重启完成后，LED 应重新回到蓝色常亮。

## 8. 管理面板

管理面板是设备的短时、物理授权维护界面。每次进入维护模式都会创建新的会话保护信息；页面只在本次 Maintenance 会话中有效。

### 8.1 Device

Device 卡片显示当前设备状态，包括：

- Firmware：当前固件版本；
- Platform：硬件平台；
- Wi-Fi：当前维护 SSID；
- BLE：BLE 是否运行，维护期间通常显示暂停；
- Recovery：ROM / USB recovery 是否保留；
- Maintenance idle timeout：当前空闲自动退出时间。

页面顶部还显示三个关键状态：

- **Secure Boot**：生产固件应为 on；
- **Flash Encryption**：生产设备应为 on；
- **OTA**：显示当前 A/B slot 及镜像是否 valid / pending。

这些字段均为只读诊断信息，不会暴露 eFuse 密钥、Flash Encryption key、MKEK 或设备私钥。

### 8.2 Firmware update

Firmware update 用于安装 Aromatic Key 的**已签名生产固件**。

操作步骤：

1. 点击 **Choose signed .bin**；
2. 选择由 Aromatic Key 构建 / 发布流程生成的 signed application `.bin`；
3. 点击 **Install update**；
4. 确认文件与大小；
5. 等待设备完成上传、签名验证和写入；
6. 设备会自动重启进入新的 A/B slot。

Aromatic Key 使用 Secure Boot + A/B OTA。更新写入 inactive slot，启动后还要通过运行确认窗口；如果新镜像无法正常启动，软件 rollback 机制可回退到上一可用 slot。

不要上传普通 ESP32 固件、未签名镜像或来源不明的 `.bin`。

### 8.3 USB applications

USB applications 卡片用于启用或禁用设备对 USB 主机暴露的应用：

- OTP
- U2F
- OpenPGP
- PIV
- OATH
- HSM Auth
- FIDO2
- Management

修改后点击 **Save configuration**。

USB interface / application 变更在**设备重启后**生效。页面会阻止把所有可用于管理的 USB 通路同时关闭。

如果不确定应如何配置，建议保持默认生产配置。

### 8.4 Configuration lock

Configuration lock 是与 YubiKey 管理语义兼容的 16-byte 配置锁。

页面输入形式为：

```text
32 个十六进制字符
```

例如长度必须恰好为 32 个 hex 字符，且不能全部为 `0`。

可执行：

- **Set / change**：设置或更新配置锁；
- **Clear lock**：清除当前配置锁。

请妥善保存配置锁。普通 USB `ykman` 管理操作会遵守该锁；物理进入的 Maintenance 会话本身则构成一次独立的设备侧维护授权。

### 8.5 Bluetooth

Bluetooth 卡片用于控制 BLE FIDO 的配对授权。

#### Open pairing window

点击 **Open pairing window** 后，设备会安排一次新的 BLE 配对窗口并重启。

正常设计为：

- 仅允许一次新的配对授权；
- 新配对窗口是短时的；
- 已存在且有效的 bond 可在正常模式下继续重连；
- 无 Maintenance 授权时，不开放任意新的 BLE 配对。

#### Reset all BLE bonds

该操作会：

1. 撤销设备保存的所有 BLE bond；
2. 重启设备；
3. 开放一次新的配对窗口。

它**不会删除 FIDO / WebAuthn credential**，只影响 BLE trust / bond 记录。

### 8.6 Maintenance

Maintenance 卡片包含会话级操作。

#### Restart device

立即重启 Aromatic Key，退出 Wi-Fi 管理模式并回到正常运行模式。

#### Reset all BLE bonds…

这是破坏性的 BLE trust 操作，会清除已有 BLE bond。执行前页面会再次确认。

## 9. 管理模式的安全边界

管理 Wi-Fi 的用途是配置与维护，不是远程密钥访问接口。

管理页面可以：

- 查看设备和安全状态；
- 修改 USB application enable mask；
- 设置 / 清除 configuration lock；
- 授权 BLE pairing；
- 重置 BLE bonds；
- 安装通过 Secure Boot 验证的签名固件；
- 重启设备。

管理页面不能：

- 读取 FIDO resident credential 私钥；
- 导出 PIV / OpenPGP 私钥；
- 导出 OATH secret；
- 导出 YubiHSM Auth secret；
- 读取 eFuse key block；
- 读取 Flash Encryption key、MKEK 或 device key；
- 修改 Secure Boot key 或进行 eFuse provisioning。

## 10. 常见问题

### 插入后不是蓝色常亮

短暂的红色启动状态属于正常现象。若长时间不回蓝：

1. 重新插拔 USB；
2. 更换 USB 端口或数据线；
3. 检查主机是否能看到 YubiKey 兼容 USB 设备；
4. 若仍无法恢复，再进入维护 / recovery 流程，不要反复进行 eFuse 或 ROM 操作。

### FIDO 操作一直等待

如果 LED 黄色闪烁，设备正在等待物理 User Presence。短按一次 BOOT；看到白色双闪即表示已接受。

如果没有黄色提示，则不要盲按。先确认应用是否真的向安全密钥发起了 FIDO 操作。

### 管理页面打不开

确认：

- LED 已绿色常亮；
- 已连接 `PicoFIDO2-XXXX`，而不是其它 Wi-Fi；
- 浏览器访问的是 `http://192.168.4.1`；
- 管理会话没有因 10 分钟无活动而自动退出。

### 找不到管理 Wi-Fi

正常模式下 Wi-Fi 不开放。重新在蓝色常亮状态下连续短按 BOOT 5 次，并等待 LED 变绿后再扫描 Wi-Fi。

### OTA 后设备没有恢复

先等待设备完成重启和 A/B 确认。如果新 slot 启动失败，软件 rollback 应恢复上一可用镜像。

如果 USB 仍无法枚举，Aromatic Key 的生产配置保留 ROM download 与 USB Serial/JTAG recovery，交由维护人员处理。

## 11. 推荐日常习惯

- 日常只把 Aromatic Key 当作 USB / BLE 安全密钥使用，不保持 Maintenance 常开；
- 只在 LED 黄色闪烁时进行 FIDO 物理确认；
- 维护完成后主动 Restart device；
- 不向设备安装来源不明的固件；
- 妥善保管 FIDO PIN、PIV PIN / PUK、OpenPGP PIN 和 Configuration lock；
- Maintenance Wi-Fi 密码是共享产品连接信息；如需更换，按“修改生产 Wi-Fi 密码”一节重新构建并 OTA 更新设备；
- 修改 USB applications 前确认至少保留自己需要的管理与认证通路。

## 12. 当前生产交互摘要

```text
正常：        蓝色常亮
处理：        青色快闪
等待触摸：    黄色闪烁
触摸成功：    白色双闪
维护模式：    绿色常亮
USB suspend： 蓝色慢闪
错误：        红色快闪

进入管理：    连续短按 BOOT 5 次
FIDO 确认：   黄色提示时短按 BOOT 1 次
管理 Wi-Fi：  PicoFIDO2-XXXX
管理地址：    http://192.168.4.1
空闲退出：    10 分钟
```

