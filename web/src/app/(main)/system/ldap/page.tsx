"use client";

import * as React from "react";

import { Loader2Icon, UsersIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import type { LDAPConfig } from "@/lib/types";

const EMPTY: LDAPConfig = {
  enabled: false,
  url: "",
  user_dn_pattern: "",
  start_tls: false,
  insecure_tls: false,
  default_role: "user",
};

export default function LDAPPage() {
  const [cfg, setCfg] = React.useState<LDAPConfig>(EMPTY);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [msg, setMsg] = React.useState<{ ok: boolean; text: string } | null>(null);

  React.useEffect(() => {
    api
      .getLDAP()
      .then((c) => setCfg(c))
      .catch((e) => setMsg({ ok: false, text: String(e instanceof Error ? e.message : e) }))
      .finally(() => setLoading(false));
  }, []);

  function set<K extends keyof LDAPConfig>(key: K, value: LDAPConfig[K]) {
    setCfg((c) => ({ ...c, [key]: value }));
    setMsg(null);
  }

  async function save() {
    setSaving(true);
    setMsg(null);
    try {
      setCfg(await api.setLDAP(cfg));
      setMsg({ ok: true, text: t("Saved.") });
    } catch (e) {
      setMsg({ ok: false, text: String(e instanceof Error ? e.message : e) });
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 p-6 text-muted-foreground">
        <Loader2Icon className="size-4 animate-spin" /> {t("Loading…")}
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-2xl space-y-4 p-4">
      <div className="flex items-center gap-2">
        <UsersIcon className="size-5 text-muted-foreground" />
        <div>
          <h1 className="text-lg font-semibold">{t("LDAP Login")}</h1>
          <p className="text-sm text-muted-foreground">
            {t("Direct bind: users sign in with their LDAP username and password; no service account is needed.")}
          </p>
        </div>
      </div>

      <Card className="space-y-4 p-4">
        <div className="flex items-center justify-between">
          <div>
            <Label>{t("Enable LDAP login")}</Label>
            <p className="text-xs text-muted-foreground">
              {t("Local accounts keep working; LDAP is tried when a local login fails.")}
            </p>
          </div>
          <Switch checked={cfg.enabled} onCheckedChange={(v) => set("enabled", v)} />
        </div>

        <div className="grid gap-2">
          <Label htmlFor="url">{t("Server URL")}</Label>
          <Input
            id="url"
            placeholder="ldaps://dir.example.com:636"
            value={cfg.url}
            onChange={(e) => set("url", e.target.value)}
          />
        </div>

        <div className="grid gap-2">
          <Label htmlFor="dn">{t("User DN pattern")}</Label>
          <Input
            id="dn"
            placeholder="uid=%s,ou=people,dc=example,dc=com"
            value={cfg.user_dn_pattern}
            onChange={(e) => set("user_dn_pattern", e.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            {t("%s is replaced by the username. For Active Directory, %s@your-domain.com also works.")}
          </p>
        </div>

        <div className="flex items-center justify-between">
          <Label htmlFor="starttls">{t("Use StartTLS (over ldap://)")}</Label>
          <Switch id="starttls" checked={cfg.start_tls} onCheckedChange={(v) => set("start_tls", v)} />
        </div>

        <div className="flex items-center justify-between">
          <div>
            <Label htmlFor="insecure">{t("Skip TLS certificate verification")}</Label>
            <p className="text-xs text-amber-600 dark:text-amber-400">
              {t("Development only — do not use in production.")}
            </p>
          </div>
          <Switch id="insecure" checked={cfg.insecure_tls} onCheckedChange={(v) => set("insecure_tls", v)} />
        </div>

        <div className="grid gap-2">
          <Label htmlFor="role">{t("Role for new LDAP users")}</Label>
          <NativeSelect
            id="role"
            value={cfg.default_role}
            onChange={(e) => set("default_role", e.target.value as LDAPConfig["default_role"])}
            className="max-w-xs"
          >
            <option value="user">{t("User")}</option>
            <option value="admin">{t("Admin")}</option>
          </NativeSelect>
        </div>

        <div className="flex items-center gap-3 pt-2">
          <Button onClick={save} disabled={saving}>
            {saving ? <Loader2Icon className="size-4 animate-spin" /> : null}
            {t("Save")}
          </Button>
          {msg && (
            <span
              className={
                msg.ok ? "text-sm text-green-600 dark:text-green-400" : "text-sm text-red-600 dark:text-red-400"
              }
            >
              {msg.text}
            </span>
          )}
        </div>
      </Card>
    </div>
  );
}
