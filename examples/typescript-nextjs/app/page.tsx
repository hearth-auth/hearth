import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import Link from "next/link";

export default function Home() {
  const accessToken = cookies().get("access_token")?.value;

  if (accessToken) {
    redirect("/dashboard");
  }

  return (
    <main>
      <h1>Hearth Next.js Example</h1>
      <p style={{ margin: "1rem 0" }}>
        This app demonstrates OIDC authentication + RBAC with Hearth.
      </p>
      <Link href="/api/auth/login">
        <button>Sign in with Hearth</button>
      </Link>
    </main>
  );
}
