# Aromatic Key 使用说明

Aromatic Key 提供 USB/BLE FIDO2、USB U2F、PIV、OpenPGP、OATH、OTP 和 HSM Auth。各应用使用各自的 PIN、凭据与管理权限。

## 日常认证

将设备接入 USB，在浏览器或应用中选择安全密钥。LED 黄色闪烁时，短按一次 BOOT 完成用户在场确认。FIDO PIN 用于用户验证，不能替代按键确认。PIV PIN/PUK 和 OpenPGP User/Admin PIN 独立于 FIDO PIN。

| LED | 状态 |
| --- | --- |
| 蓝色常亮 | 就绪 |
| 青色快闪 | 正在处理 |
| 黄色闪烁 | 等待按键确认 |
| 白色双闪 | 已接受确认 |
| 绿色常亮 | Wi-Fi 维护 |
| 蓝色慢闪 | USB suspend |
| 红色快闪 | 错误 |

## 进入维护

1. 等待设备就绪，连续短按 BOOT 五次。
2. LED 变绿后连接 `Aromatic-Key-XXXX` 热点，公开默认密码为 `Aromatic-Key`。
3. 浏览器打开 `http://192.168.4.1`。

生产维护一次只接受一台 Wi-Fi 客户端，空闲十分钟后重启。页面的 Restart device 可主动退出。维护会停止 BLE，重启后恢复正常 USB/BLE 模式。

## 管理页面

Device 显示固件、平台、维护 SSID、安全启动、Flash Encryption、恢复接口和 A/B slot 状态。

USB applications 控制 OTP、U2F、FIDO2、PIV、OpenPGP、OATH、HSM Auth 和 Management。保存后重启生效，至少保留需要的认证与管理通路。

Configuration lock 使用 32 个十六进制字符表示 16 字节配置锁，不能全部为零。普通 USB 管理遵守该锁；物理进入的维护会话可设置、修改或清除它。

## 蓝牙配对

在维护页面选择 Open pairing window，设备安排一次短时的新配对授权并重启。正常模式下，有效的已有 bond 可以重连。

Reset all BLE bonds 会撤销所有设备端蓝牙配对，并安排一次新的配对窗口。它保留 FIDO/WebAuthn 凭据。重新配对前也应在主机蓝牙设置中忘记该设备，然后在窗口内完成系统配对并测试认证。

## 固件更新

在 Firmware update 中选择项目构建流程生成的已签名应用 `.bin`，点击 Install update。更新写入非活动 slot，验证后重启；新镜像须通过运行确认，启动失败时可由 A/B rollback 恢复。

仅安装可信来源、匹配设备安全配置的签名镜像。OTA 保留应用凭据。eFuse provisioning 和 ROM 恢复由维护人员使用主机工具执行。

## 重置与恢复

Applet reset 删除对应应用的数据和 PIN；全设备 application-data reset 会清除多个应用。执行前确认目标和数据备份。`tools/factory_reset_preflight.py` 默认只读取身份与版本，显式 `--reset` 后还需输入确认。

设备持续异常时可先重新插拔 USB、更换数据线并检查主机枚举。等待用户在场时只按一次 BOOT。维护页面不可达时，检查热点连接、地址及会话是否已超时。

妥善保存各应用 PIN、PUK 和配置锁，维护完成后重启回到正常模式。
