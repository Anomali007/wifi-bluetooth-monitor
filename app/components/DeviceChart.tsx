"use client";

import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  BarChart,
  Bar,
  XAxis,
  Tooltip as RechartsTooltip,
  CartesianGrid,
  Legend,
} from "recharts";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  ChartLegend,
  ChartLegendContent,
} from "@/components/ui/chart";

interface NetworkDevice {
  name: string;
  identifier: string;
  signal_strength: number | null;
  timestamp: string;
  device_type: string;
}

export default function DeviceChart() {
  const [data, setData] = useState<NetworkDevice[]>([]);

  useEffect(() => {
    async function fetchDevices() {
      try {
        const result: NetworkDevice[] = await invoke("scan_networks");
        setData(result);
      } catch (error) {
        console.error("Error fetching devices:", error);
      }
    }

    fetchDevices();
    const interval = setInterval(fetchDevices, 60000); // Refresh every minute
    return () => clearInterval(interval);
  }, []);

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
      color: "hsl(var(--chart-WiFi))",
    },
    Bluetooth: {
      label: "Bluetooth",
      color: "hsl(var(--chart-Bluetooth))",
    },
  } as const;

  return (
    <ChartContainer config={chartConfig} className="min-h-[400px] w-full">
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
        <RechartsTooltip content={<ChartTooltipContent />} />
        <ChartLegend content={<ChartLegendContent nameKey="device_type" />} />
        <Bar
          dataKey="signal_strength"
          name="Signal Strength"
          fill={({ payload }) =>
            payload.device_type === "Wi-Fi"
              ? "var(--color-WiFi)"
              : "var(--color-Bluetooth)"
          }
          radius={4}
        />
      </BarChart>
    </ChartContainer>
  );
}
