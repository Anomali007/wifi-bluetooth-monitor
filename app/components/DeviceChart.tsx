"use client";

import {
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  CartesianGrid,
} from "recharts";
import {
  ChartContainer,
  ChartTooltipContent,
  ChartLegend,
  ChartLegendContent,
} from "@/components/ui/chart";

export interface ChartRow {
  name: string;
  signal_strength: number | null;
  device_type: "Wi-Fi" | "Bluetooth";
}

export default function DeviceChart({ data }: { data: ChartRow[] }) {
  // Prepare data for the chart
  const chartData = data.map((device) => ({
    name: device.name,
    signal_strength: device.signal_strength,
    device_type: device.device_type,
  }));

  // Chart configuration
  const chartConfig = {
    WiFi: {
      label: "Wi-Fi",
      color: "hsl(var(--chart-1))",
    },
    Bluetooth: {
      label: "Bluetooth",
      color: "hsl(var(--chart-2))",
    },
  } as const;

  return (
    <ChartContainer config={chartConfig} className="min-h-[320px] w-full">
      <BarChart
        data={chartData}
        width={600}
        height={400}
        margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
      >
        <CartesianGrid vertical={false} strokeDasharray="3 3" />
        <XAxis
          dataKey="name"
          tickLine={false}
          tickMargin={10}
          axisLine={false}
        />
        <YAxis domain={[0, 100]} tickLine={false} axisLine={false} width={32} />
        <RechartsTooltip content={<ChartTooltipContent />} />
        <ChartLegend content={<ChartLegendContent nameKey="device_type" />} />
        <Bar dataKey="signal_strength" name="Signal Strength" radius={4} isAnimationActive={false}>
          {chartData.map((row, i) => (
            <Cell
              key={i}
              fill={
                row.device_type === "Wi-Fi"
                  ? "var(--color-WiFi)"
                  : "var(--color-Bluetooth)"
              }
            />
          ))}
        </Bar>
      </BarChart>
    </ChartContainer>
  );
}
