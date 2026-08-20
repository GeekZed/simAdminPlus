import { Box, Card, CardContent, Typography, Stack, Switch, Chip } from '@mui/material'
import { NetworkCheck, FlightTakeoff, TravelExplore, Tune, PhoneInTalk, DataUsage } from '@mui/icons-material'
import type { AirplaneModeResponse, RoamingResponse, VolteControlResponse } from '@/api/types'

interface QuickControlsProps {
  dataStatus: boolean
  airplaneMode: AirplaneModeResponse | null
  roaming: RoamingResponse | null
  volte: VolteControlResponse | null
  onToggleData: () => void
  onToggleAirplaneMode: () => void
  onToggleRoaming: () => void
  onToggleVolte: () => void
  packageUsageVisible: boolean
  onTogglePackageUsage: () => void
}

export function QuickControls({
  dataStatus,
  airplaneMode,
  roaming,
  volte,
  onToggleData,
  onToggleAirplaneMode,
  onToggleRoaming,
  onToggleVolte,
  packageUsageVisible,
  onTogglePackageUsage,
}: QuickControlsProps) {
  const volteTransport = volte?.runtime.transport.toLowerCase().includes('ipsec')
    ? 'IPsec'
    : volte?.runtime.transport.toLowerCase().includes('udp')
      ? 'UDP'
      : ''
  const volteLabel = !volte?.enabled
    ? '已关闭'
    : volte.runtime.registered
      ? `已注册${volteTransport ? ` · ${volteTransport}` : ''}`
      : /failed|waiting|disconnected|interface_failed/i.test(volte.runtime.phase)
        ? '异常'
        : '启动中'
  const volteColor = !volte?.enabled
    ? 'default'
    : volte.runtime.registered
      ? 'success'
    : /failed|waiting|disconnected|interface_failed/i.test(volte.runtime.phase)
      ? 'error'
      : 'warning'

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box display="flex" alignItems="center" gap={1} mb={2}>
          <Tune color="primary" />
          <Typography variant="subtitle1" fontWeight={700}>快捷控制</Typography>
        </Box>

        <Stack spacing={2}>
          <Box display="flex" alignItems="center" justifyContent="space-between">
            <Box display="flex" alignItems="center" gap={1}><DataUsage color={packageUsageVisible ? 'primary' : 'disabled'} /><Typography variant="body2">套餐信息</Typography></Box>
            <Switch checked={packageUsageVisible} onChange={onTogglePackageUsage} color="primary" size="small" />
          </Box>
          <Box display="flex" alignItems="center" justifyContent="space-between">
            <Box display="flex" alignItems="center" gap={1}>
              <NetworkCheck color={dataStatus ? 'success' : 'disabled'} />
              <Typography variant="body2">数据连接</Typography>
            </Box>
            <Switch
              checked={dataStatus}
              onChange={() => {
                void onToggleData()
              }}
              color="success"
              size="small"
            />
          </Box>

          <Box display="flex" alignItems="center" justifyContent="space-between">
            <Box display="flex" alignItems="center" gap={1}>
              <PhoneInTalk color={volte?.runtime.registered ? 'success' : 'disabled'} />
              <Typography variant="body2">VoLTE</Typography>
              <Chip label={volteLabel} title={volte?.runtime.last_error || volte?.runtime.phase} size="small" color={volteColor} sx={{ height: 18, fontSize: '0.65rem' }} />
            </Box>
            <Switch
              checked={volte?.enabled || false}
              onChange={() => void onToggleVolte()}
              color="success"
              size="small"
            />
          </Box>

          <Box display="flex" alignItems="center" justifyContent="space-between">
            <Box display="flex" alignItems="center" gap={1}>
              <TravelExplore color={roaming?.roaming_allowed ? 'info' : 'disabled'} />
              <Typography variant="body2">漫游数据</Typography>
              {roaming?.is_roaming && (
                <Chip label="漫游中" size="small" color="warning" sx={{ height: 18, fontSize: '0.65rem' }} />
              )}
            </Box>
            <Switch
              checked={roaming?.roaming_allowed || false}
              onChange={() => {
                void onToggleRoaming()
              }}
              color="info"
              size="small"
            />
          </Box>

          <Box display="flex" alignItems="center" justifyContent="space-between">
            <Box display="flex" alignItems="center" gap={1}>
              <FlightTakeoff color={airplaneMode?.enabled ? 'warning' : 'disabled'} />
              <Typography variant="body2">飞行模式</Typography>
            </Box>
            <Switch
              checked={airplaneMode?.enabled || false}
              onChange={() => {
                void onToggleAirplaneMode()
              }}
              color="warning"
              size="small"
            />
          </Box>
        </Stack>
      </CardContent>
    </Card>
  )
}
