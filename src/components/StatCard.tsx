interface Props {
  label: string;
  value: string;
  sub?: string;
  accent?: string;
  icon?: React.ReactNode;
}

export default function StatCard({ label, value, sub, accent = "text-zinc-100", icon }: Props) {
  return (
    <div className="glass-card relative overflow-hidden rounded-2xl p-4">
      <div className="flex items-center justify-between">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-zinc-400">{label}</div>
        {icon && <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-white/[0.05] text-zinc-300">{icon}</div>}
      </div>
      <div className={`mt-2 text-2xl font-bold tracking-tight ${accent}`}>{value}</div>
      {sub && <div className="mt-1 text-xs text-zinc-500">{sub}</div>}
    </div>
  );
}

