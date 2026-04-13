import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Providers } from "./providers";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });

export const metadata: Metadata = {
  title: {
    default: "AttackTrace | Attack Surface Management",
    template: "%s | AttackTrace",
  },
  description:
    "Attack Surface Management — discover, monitor, and remediate your external attack surface.",
  keywords: ["attack surface management", "security", "recon", "vulnerability management"],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.variable} font-sans antialiased bg-zinc-950 text-zinc-100`}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
