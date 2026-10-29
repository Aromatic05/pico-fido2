# Pico FIDO2

FIDO2/U2F、OpenPGP、PIV、OATH、OTP 与 HSM Auth 固件，支持 Raspberry Pi Pico 和 ESP32-S3。该项目基于 Pico FIDO2 社区版。

Aromatic Key 的按钮、LED、蓝牙和维护页面操作见 [使用说明](docs/Aromatic-Key-User-Guide.zh-CN.md)。

## 获取源码

```sh
git submodule update --init --recursive
```

## Raspberry Pi Pico

安装 Pico SDK 和 ARM 工具链，设置 `PICO_SDK_PATH`：

```sh
cmake -S . -B build -DPICO_BOARD=pico
cmake --build build -j2
```

按住 BOOTSEL 接入 USB，将 `build/pico_fido2.uf2` 复制到设备。

## ESP32-S3

使用 ESP-IDF v5.5，先激活其 `export.sh`，再准备 Ed25519 后端：

```sh
./tools/prepare_esp32s3_ed25519.sh
./tools/esp32s3_bringup.sh build
```

可逆 bring-up 使用开发根密钥，只适用于开发。生产设备使用主机生成的 provisioning material、安全启动、Flash Encryption 和签名镜像。根密钥与 provisioning material 必须在仓库外保存。

已完成 provisioning 的 A/B 设备可构建签名 OTA：

```sh
./tools/build_esp32s3_ab_ota_update_bundle.sh /private/provisioning build-ab-ota-update 1.0.0 0 production
```

最后两个参数分别是安全版本和维护配置；`production` 使用物理按钮进入维护。开发配置 `development` 允许 USB 开启维护且绕过页面授权检查。安全版本必须不低于设备 eFuse floor。

在维护页面安装生成的签名应用镜像。开发设备也可使用 `tools/dev_ota.py`；先通过系统网络设置连接维护热点，再运行：

```sh
./tools/dev_ota.py build-ab-ota-update/pico_fido2-ota-signed.bin --serial <device-serial>
```

`tools/esp32s3_provision.py` 和 `tools/esp32s3_update.py` 的 `--help` 列出主机 provisioning、只读 preflight、ROM 更新和回读参数。烧写 eFuse 不可逆；设备身份、当前 floor 和目标配置由命令参数显式指定。

## 软件验证

Host 构建需要 C/C++ 工具链、CMake、Mbed TLS 依赖和相应 Python 协议库。启用 EdDSA 的 Host 测试通过 `tools/prepare_host_eddsa_mbedtls.sh` 准备临时补丁副本。

```sh
./tools/test_software.sh
./tools/test_fido_host_container.sh
./tools/test_piv_host_container.sh
./tools/test_openpgp_host_container.sh
```

软件入口包含实际协议、传输、持久化和故障注入测试；独立状态模型只用于设计约束。ESP32-S3 QEMU 测试入口为 `tools/test_esp32s3_*_qemu.sh`，使用一次性虚拟 Flash/eFuse。

## 实体测试

仅在持有授权、使用可丢弃测试凭据时运行。测试可能修改 PIN、创建或删除凭据、耗尽重试次数或执行 applet reset；先查看对应入口参数并准备恢复状态。运行输出、私密 checkpoint 和验收记录放在仓库外。

```sh
./tools/test_hil_fido_capacity.sh --pin-file /private/test-pin.txt --journal /private/hil/capacity.json --evidence-dir /private/hil
./tools/test_hil_fido_pin.sh change --action seed --state-dir /private/test-state --evidence-dir /private/hil
PYTHONPATH=tests python3 -m hil.piv keys --help
PYTHONPATH=tests python3 -m hil.openpgp keys --help
```

`hil.applet_inventory` 建立基线，`hil.applet_sentinels` 准备并验证 sibling applet；`hil.applet_reset` 提供各 applet 的 reset/恢复用例。FIDO 容量用例保留 journal、256/257 边界、真实 USB 重插、身份和公钥比较、独立验签、删除与补充注册。

## 许可证

许可证及各依赖的授权见仓库内 LICENSE 和子模块声明。USB VID/PID 的发布使用需获得所有者授权。
