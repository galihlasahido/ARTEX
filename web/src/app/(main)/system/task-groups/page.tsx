"use client";

import * as React from "react";

import { Loader2Icon, PlusIcon, Trash2Icon, UsersRoundIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import type { TaskGroup } from "@/lib/types";

export default function TaskGroupsPage() {
  const [groups, setGroups] = React.useState<TaskGroup[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [name, setName] = React.useState("");
  const [error, setError] = React.useState("");

  const reload = React.useCallback(async () => {
    try {
      const r = await api.listTaskGroups();
      setGroups(r.groups ?? []);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void reload();
  }, [reload]);

  async function create() {
    const n = name.trim();
    if (!n) return;
    setError("");
    try {
      await api.createTaskGroup(n);
      setName("");
      await reload();
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  }

  return (
    <div className="mx-auto w-full max-w-3xl space-y-4 p-4">
      <div className="flex items-center gap-2">
        <UsersRoundIcon className="size-5 text-muted-foreground" />
        <div>
          <h1 className="text-lg font-semibold">{t("Task Groups")}</h1>
          <p className="text-sm text-muted-foreground">
            {t("Assign users to a group; every member can access the tasks placed in that group.")}
          </p>
        </div>
      </div>

      <Card className="flex flex-wrap items-end gap-2 p-4">
        <div className="grid flex-1 gap-2">
          <Label htmlFor="new-group">{t("New group name")}</Label>
          <Input
            id="new-group"
            value={name}
            placeholder={t("e.g. Pentest team A")}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && create()}
          />
        </div>
        <Button onClick={create} disabled={!name.trim()}>
          <PlusIcon className="size-4" /> {t("Create")}
        </Button>
      </Card>

      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

      {loading ? (
        <div className="flex items-center gap-2 text-muted-foreground">
          <Loader2Icon className="size-4 animate-spin" /> {t("Loading…")}
        </div>
      ) : groups.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("No task groups yet.")}</p>
      ) : (
        <div className="space-y-3">
          {groups.map((g) => (
            <GroupCard key={g.id} group={g} onChanged={reload} />
          ))}
        </div>
      )}
    </div>
  );
}

function GroupCard({ group, onChanged }: { group: TaskGroup; onChanged: () => Promise<void> }) {
  const [members, setMembers] = React.useState((group.members ?? []).join(", "));
  const [busy, setBusy] = React.useState(false);
  const [saved, setSaved] = React.useState(false);

  async function saveMembers() {
    setBusy(true);
    setSaved(false);
    try {
      const list = members
        .split(/[,\n]/)
        .map((s) => s.trim())
        .filter(Boolean);
      await api.setTaskGroupMembers(group.id, list);
      setSaved(true);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    try {
      await api.deleteTaskGroup(group.id);
      await onChanged();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="space-y-2 p-4">
      <div className="flex items-center justify-between">
        <h2 className="font-medium">{group.name}</h2>
        <Button variant="ghost" size="sm" onClick={remove} disabled={busy} className="text-red-600 dark:text-red-400">
          <Trash2Icon className="size-4" /> {t("Delete")}
        </Button>
      </div>
      <Label htmlFor={`m-${group.id}`} className="text-xs text-muted-foreground">
        {t("Members (usernames, comma-separated)")}
      </Label>
      <Input
        id={`m-${group.id}`}
        value={members}
        placeholder="alice, bob"
        onChange={(e) => {
          setMembers(e.target.value);
          setSaved(false);
        }}
      />
      <div className="flex items-center gap-3">
        <Button size="sm" onClick={saveMembers} disabled={busy}>
          {busy ? <Loader2Icon className="size-4 animate-spin" /> : null} {t("Save members")}
        </Button>
        {saved && <span className="text-sm text-green-600 dark:text-green-400">{t("Saved.")}</span>}
      </div>
    </Card>
  );
}
