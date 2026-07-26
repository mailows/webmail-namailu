"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2, AlertCircle } from "lucide-react";
import { useAuthStore } from "@/stores/auth-store";
import { toRouterPath } from "@/lib/browser-navigation";
import { locales } from "@/i18n/routing";

/**
 * Návrat z IdP (fáze 3).
 *
 * Callback `/api/auth/oidc/callback` vyřídil celou výměnu na serveru a poslal sem
 * prohlížeč — v URL proto **není žádný kód ani token**, jen `next`. Tahle stránka jen
 * vyzvedne access token do paměti a pustí uživatele dál.
 *
 * Není pod `/auth/`: ten prefix na apexu patří ve výchozí konfiguraci NPM Stalwartu,
 * takže by se sem prohlížeč vůbec nedostal.
 */
function ResumeInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const loginWithOidc = useAuthStore((s) => s.loginWithOidc);
  const [failed, setFailed] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    // React 18 v dev módu mountuje dvakrát; druhé volání by zbytečně sáhlo pro další token.
    if (started.current) return;
    started.current = true;

    const next = searchParams.get("next") || "/";
    // `next` přijde z login flow jako window.location.pathname — tedy S LOCALE prefixem
    // (např. /cs). next-intl router přidá locale sám, takže ho tady stripneme, jinak by
    // vzniklo /cs/cs. Stejně to funguje pro /cs/calendar → /calendar.
    const localeRe = new RegExp(`^/(${locales.join("|")})(?=/|$)`);
    const stripped = next.replace(localeRe, "") || "/";
    const safeNext = stripped.startsWith("/") && !stripped.startsWith("//") ? stripped : "/";

    loginWithOidc()
      .then((ok) => {
        if (ok) router.replace(toRouterPath(safeNext));
        else setFailed(true);
      })
      .catch(() => setFailed(true));
  }, [loginWithOidc, router, searchParams]);

  if (failed) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-6 text-center">
        <AlertCircle className="h-8 w-8 text-destructive" aria-hidden />
        <p className="text-sm text-muted-foreground">
          Přihlášení se nepodařilo dokončit.
        </p>
        <a className="text-sm underline" href="/">
          Zkusit znovu
        </a>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center">
      <Loader2 className="h-6 w-6 animate-spin" aria-label="Přihlašuji" />
    </div>
  );
}

export default function OidcResumePage() {
  return (
    <Suspense fallback={null}>
      <ResumeInner />
    </Suspense>
  );
}
