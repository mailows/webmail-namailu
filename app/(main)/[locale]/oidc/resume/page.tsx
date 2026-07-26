"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { useRouter } from "@/i18n/navigation";
import { useSearchParams } from "next/navigation";
import { Loader2, AlertCircle } from "lucide-react";
import { useAuthStore } from "@/stores/auth-store";
import { stripLocalePrefix, toRouterPath } from "@/lib/browser-navigation";

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

    const rawNext = searchParams.get("next") || "/";
    // next-intl router přidá locale prefix sám, takže `next` musí být locale-relativní.
    // Po root fixu (stripLocalePrefix při ukládání redirect_after_login) by už měl být
    // bez locale, ale pro jistotu (staré pending cookies, přímé linky) stripneme znovu.
    const safeNext = stripLocalePrefix(rawNext);

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
