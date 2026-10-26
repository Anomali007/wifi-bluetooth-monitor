import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import { MonitorProvider } from "@/components/monitor-provider";
import CommandPalette from "@/components/command-palette";
import Nav from "@/components/nav";

const geistSans = localFont({
  src: "./fonts/GeistVF.woff",
  variable: "--font-geist-sans",
  weight: "100 900",
});
const geistMono = localFont({
  src: "./fonts/GeistMonoVF.woff",
  variable: "--font-geist-mono",
  weight: "100 900",
});

export const metadata: Metadata = {
  title: "Network Security Monitor",
  description: "Passive Wi-Fi and Bluetooth monitor (listen-only unless you turn on the network sweep)",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <MonitorProvider>
          <Nav />
          <CommandPalette />
          <main className="container mx-auto p-4">{children}</main>
        </MonitorProvider>
      </body>
    </html>
  );
}
