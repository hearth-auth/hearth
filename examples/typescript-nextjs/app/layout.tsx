import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Hearth Next.js Example",
  description: "Protected Next.js app backed by Hearth identity",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
