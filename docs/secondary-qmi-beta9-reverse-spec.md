# beta9 secondary-qmi-init 逆向规格

该启动器负责在 ModemManager 启动前准备 DATA6 的第二个 QMI 端点。它与普通数据拨号不同，目标是固定并持有 RPMSG/QMI 设备，避免 ModemManager 抢占或重新枚举端点。

## 已确认的设备约束

- 先加载 `rpmsg_wwan_ctrl` 内核模块。
- 在 `/sys/bus/rpmsg/devices/*/name` 中查找 `DATA6_CNTL`。
- 使用 `driver_override` 和 `rpmsg_wwan_ctrl` 的 `bind` 节点绑定 DATA6。
- 绑定后需要确认 stock RPMSG 驱动暴露 WWAN 端口；beta9 会区分 primary QMI 与 secondary QMI，避免多个 WWAN 端口同时出现时误选。
- beta9 使用 `/run/simadmin/secondary-qmi-device` 发布已选中的 QMI 设备路径。
- QMI 端点打开参数包含：
  - `--device-open-qmi`
  - `--device-open-net=net-raw-ip|net-no-qos-header`
  - `--get-service-version-info`
- 运行时使用环境变量覆盖设备选择：
  - `SIMADMIN_PRIMARY_QMI_DEVICE`
  - `SIMADMIN_SECONDARY_QMI_DEVICE`
  - `SIMADMIN_SECONDARY_QMI_NETDEV`

## 生命周期要求

1. ModemManager 启动前完成 DATA6 绑定。
2. 初始化成功后持续持有第二路 QMI 端点。
3. 端点被替换或消失时写入错误状态并退出，让 systemd 按策略重启。
4. 主 QMI 端点必须始终保持独立，secondary-qmi-init 不能重置主数据 bearer。

## 与 VoLTE 的关系

`secondary-qmi-init` 只负责端点准备；beta9 的 VoLTE runtime 随后在该端点上建立 IPv6 IMS bearer，再执行 P-CSCF、USIM-AKA、XFRM/IPsec、SIP REGISTER 和 IMS SMS。两者不能合并成普通的 ModemManager data profile。
