"use client";

export default function NumberField({
  label,
  value,
  min,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  onChange: (n: number) => void;
}) {
  return (
    <label className="flex items-center justify-between gap-4 text-sm">
      {label}
      <input
        type="number"
        min={min}
        value={value}
        onChange={(e) => onChange(Math.max(min, Number(e.target.value) || min))}
        className="w-24 rounded-md border bg-background px-2 py-1"
      />
    </label>
  );
}
