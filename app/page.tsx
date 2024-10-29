import DeviceChart from "./components/DeviceChart";

export default function Home() {
  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">Network Security Monitor</h1>
      <DeviceChart />
    </div>
  );
}
