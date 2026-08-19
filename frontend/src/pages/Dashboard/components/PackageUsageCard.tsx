import { Card, CardContent, Box, Typography, Stack, Chip, Button, Dialog, DialogTitle, DialogContent, DialogActions, TextField, LinearProgress } from '@mui/material'
import { useState } from 'react'
import { DataUsage } from '@mui/icons-material'
import type { PackageUsageResponse } from '@/api/types'
import { api } from '@/api/current'

function gb(bytes: number) {
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)}GB`
}

function UsageRow({ title, remaining, used, total }: { title: string; remaining: number; used: number; total: number }) {
  const percent = total > 0 ? Math.min(100, Math.max(0, (used / total) * 100)) : 0
  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="baseline" gap={1}>
        <Typography variant="body2" fontWeight={700}>{title}</Typography>
        <Typography variant="caption" color="success.main" fontWeight={700}>{percent.toFixed(0)}% 已用</Typography>
      </Box>
      <LinearProgress
        variant="determinate"
        value={percent}
        color="success"
        sx={{ mt: 0.75, height: 7, borderRadius: 4, bgcolor: 'success.50', '& .MuiLinearProgress-bar': { borderRadius: 4 } }}
      />
      <Typography variant="caption" color="text.secondary">
        剩余 {gb(remaining)} · 已用 {gb(used)} · 总量 {gb(total)}
      </Typography>
    </Box>
  )
}

export function PackageUsageCard({ usage }: { usage: PackageUsageResponse | null }) {
  const [open, setOpen] = useState(false)
  const [values, setValues] = useState({ generalTotal: '', generalUsed: '', directedTotal: '', directedUsed: '' })
  const [saving, setSaving] = useState(false)
  const set = (key: keyof typeof values) => (event: React.ChangeEvent<HTMLInputElement>) => setValues({ ...values, [key]: event.target.value })
  const save = async () => {
    const gbToBytes = (value: string) => Math.round(Number(value) * 1024 * 1024 * 1024)
    if (![values.generalTotal, values.generalUsed, values.directedTotal, values.directedUsed].every((value) => Number.isFinite(Number(value)) && Number(value) >= 0)) return
    setSaving(true)
    try { await api.calibratePackageUsage({ general_total_bytes: gbToBytes(values.generalTotal), general_used_bytes: gbToBytes(values.generalUsed), directed_total_bytes: gbToBytes(values.directedTotal), directed_used_bytes: gbToBytes(values.directedUsed) }); setOpen(false); window.location.reload() } finally { setSaving(false) }
  }
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box display="flex" alignItems="center" gap={1} mb={2}>
          <DataUsage color="primary" />
          <Typography variant="subtitle1" fontWeight={700}>套餐信息</Typography>
          <Chip label={usage?.enabled ? '手动校准' : '未校准'} size="small" sx={{ ml: 'auto' }} />
          <Button size="small" onClick={() => setOpen(true)}>校准</Button>
        </Box>
        {usage?.enabled ? (
          <Stack spacing={1.5}>
            <UsageRow title="国内通用流量" remaining={usage.general_remaining_bytes} used={usage.general_used_bytes} total={usage.general_total_bytes} />
            <UsageRow title="定向流量" remaining={usage.directed_remaining_bytes} used={usage.directed_used_bytes} total={usage.directed_total_bytes} />
          </Stack>
        ) : <Typography variant="body2" color="text.secondary">请在套餐设置中完成首次校准</Typography>}
      </CardContent>
      <Dialog open={open} onClose={() => setOpen(false)}>
        <DialogTitle>校准套餐信息（GB）</DialogTitle>
        <DialogContent sx={{ display: 'grid', gap: 1.5, pt: 2 }}>
          <TextField label="国内通用总量" value={values.generalTotal} onChange={set('generalTotal')} type="number" />
          <TextField label="国内通用已用" value={values.generalUsed} onChange={set('generalUsed')} type="number" />
          <TextField label="定向流量总量" value={values.directedTotal} onChange={set('directedTotal')} type="number" />
          <TextField label="定向流量已用" value={values.directedUsed} onChange={set('directedUsed')} type="number" />
        </DialogContent>
        <DialogActions><Button onClick={() => setOpen(false)}>取消</Button><Button onClick={() => void save()} disabled={saving}>保存</Button></DialogActions>
      </Dialog>
    </Card>
  )
}
