"use client";

import * as React from "react";

import { MoreHorizontal, ShieldCheck, UserPlus } from "lucide-react";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { t } from "@/i18n";
import type { Role } from "@/lib/access";
import { ApiError, api } from "@/lib/api";
import type { User } from "@/lib/types";

function roleLabel(role: Role): string {
  return role === "admin" ? t("Administrator") : t("User");
}

function errMessage(e: unknown, fallback: string): string {
  return e instanceof ApiError && e.message ? e.message : fallback;
}

// The password rule shown and checked in the dialogs. It mirrors the backend
// (server validateComplexPassword); the server is authoritative.
const PASSWORD_RULE = "At least 12 characters, with an uppercase letter, a lowercase letter, a digit, and a symbol.";

// passwordInvalid reports whether pw fails the complexity rule.
function passwordInvalid(pw: string): boolean {
  return pw.length < 12 || !/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/[0-9]/.test(pw) || !/[^A-Za-z0-9]/.test(pw);
}

export default function UserManagementPage() {
  const [users, setUsers] = React.useState<User[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  const [createOpen, setCreateOpen] = React.useState(false);
  const [resetFor, setResetFor] = React.useState<User | null>(null);
  const [deleteFor, setDeleteFor] = React.useState<User | null>(null);

  const load = React.useCallback(async () => {
    try {
      setUsers(await api.users());
    } catch (e) {
      toast.error(errMessage(e, t("Could not load users")));
    } finally {
      setLoaded(true);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function setRole(u: User, role: Role) {
    if (u.role === role) return;
    try {
      await api.updateUser(u.id, { role });
      toast.success(t("User updated"));
      await load();
    } catch (e) {
      toast.error(errMessage(e, t("Could not update user")));
    }
  }

  async function setActive(u: User, active: boolean) {
    try {
      await api.updateUser(u.id, { active });
      toast.success(t("User updated"));
      await load();
    } catch (e) {
      toast.error(errMessage(e, t("Could not update user")));
    }
  }

  async function remove(u: User) {
    try {
      await api.deleteUser(u.id);
      toast.success(t("User deleted"));
      setDeleteFor(null);
      await load();
    } catch (e) {
      toast.error(errMessage(e, t("Could not delete user")));
    }
  }

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{t("User Management")}</h1>
          <p className="text-muted-foreground text-sm">{t("Manage login accounts and their roles")}</p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <UserPlus className="size-4" />
          {t("New user")}
        </Button>
      </div>

      <p className="text-muted-foreground text-sm">
        {t(
          "Administrators can reach every page, including system configuration and user management. Users can reach only the operator pages (tasks, chat, findings, traffic, approvals).",
        )}
      </p>

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("Username")}</TableHead>
              <TableHead>{t("Role")}</TableHead>
              <TableHead>{t("Status")}</TableHead>
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {/* The built-in ARTEX admin is always an administrator and is managed from the login page. */}
            <TableRow>
              <TableCell className="font-medium">
                <span className="flex items-center gap-2">
                  <ShieldCheck className="size-4 text-muted-foreground" />
                  ARTEX
                  <Badge variant="secondary">{t("Built-in")}</Badge>
                </span>
              </TableCell>
              <TableCell>{t("Administrator")}</TableCell>
              <TableCell>
                <Badge variant="outline">{t("Active")}</Badge>
              </TableCell>
              <TableCell />
            </TableRow>

            {users.map((u) => (
              <TableRow key={u.id}>
                <TableCell className="font-medium">{u.username}</TableCell>
                <TableCell>
                  <Badge variant={u.role === "admin" ? "default" : "secondary"}>{roleLabel(u.role)}</Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={u.active ? "outline" : "destructive"}>{u.active ? t("Active") : t("Inactive")}</Badge>
                </TableCell>
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon" className="size-8">
                        <MoreHorizontal className="size-4" />
                        <span className="sr-only">{t("Actions")}</span>
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      {u.role === "admin" ? (
                        <DropdownMenuItem onClick={() => setRole(u, "user")}>{t("Make user")}</DropdownMenuItem>
                      ) : (
                        <DropdownMenuItem onClick={() => setRole(u, "admin")}>
                          {t("Make administrator")}
                        </DropdownMenuItem>
                      )}
                      {u.active ? (
                        <DropdownMenuItem onClick={() => setActive(u, false)}>{t("Deactivate")}</DropdownMenuItem>
                      ) : (
                        <DropdownMenuItem onClick={() => setActive(u, true)}>{t("Activate")}</DropdownMenuItem>
                      )}
                      <DropdownMenuItem onClick={() => setResetFor(u)}>{t("Reset password")}</DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem variant="destructive" onClick={() => setDeleteFor(u)}>
                        {t("Delete")}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            ))}

            {loaded && users.length === 0 && (
              <TableRow>
                <TableCell colSpan={4} className="text-muted-foreground py-8 text-center text-sm">
                  {t("No additional accounts yet.")}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      <CreateUserDialog open={createOpen} onOpenChange={setCreateOpen} onCreated={load} />
      <ResetPasswordDialog user={resetFor} onClose={() => setResetFor(null)} />
      <AlertDialog open={deleteFor !== null} onOpenChange={(v) => !v && setDeleteFor(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("Delete this account?")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("This permanently removes the account and ends its active sessions.")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("Cancel")}</AlertDialogCancel>
            <AlertDialogAction onClick={() => deleteFor && remove(deleteFor)}>{t("Delete")}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function CreateUserDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onCreated: () => Promise<void>;
}) {
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [role, setRole] = React.useState<Role>("user");
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (open) {
      setUsername("");
      setPassword("");
      setRole("user");
    }
  }, [open]);

  async function submit() {
    setSaving(true);
    try {
      await api.createUser(username.trim(), password, role);
      toast.success(t("User created"));
      onOpenChange(false);
      await onCreated();
    } catch (e) {
      toast.error(errMessage(e, t("Could not create user")));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("New user")}</DialogTitle>
          <DialogDescription>{t("Create a login account with a role.")}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="new-username">{t("Username")}</Label>
            <Input
              id="new-username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="off"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="new-password">{t("Password")}</Label>
            <Input
              id="new-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
            />
            <p
              className={`text-xs ${password !== "" && passwordInvalid(password) ? "text-destructive" : "text-muted-foreground"}`}
            >
              {t(PASSWORD_RULE)}
            </p>
          </div>
          <div className="space-y-1.5">
            <Label>{t("Role")}</Label>
            <Select value={role} onValueChange={(v) => setRole(v as Role)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="user">{t("User")}</SelectItem>
                <SelectItem value="admin">{t("Administrator")}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("Cancel")}
          </Button>
          <Button onClick={submit} disabled={saving || username.trim() === "" || passwordInvalid(password)}>
            {t("Create")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ResetPasswordDialog({ user, onClose }: { user: User | null; onClose: () => void }) {
  const [password, setPassword] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (user) setPassword("");
  }, [user]);

  async function submit() {
    if (!user) return;
    setSaving(true);
    try {
      await api.updateUser(user.id, { password });
      toast.success(t("Password reset"));
      onClose();
    } catch (e) {
      toast.error(errMessage(e, t("Could not reset password")));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={user !== null} onOpenChange={(v) => !v && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("Reset password")}</DialogTitle>
          <DialogDescription>
            {user ? t("Set a new password for {name}.").replace("{name}", user.username) : ""}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-1.5">
          <Label htmlFor="reset-password">{t("New password")}</Label>
          <Input
            id="reset-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
          />
          <p
            className={`text-xs ${password !== "" && passwordInvalid(password) ? "text-destructive" : "text-muted-foreground"}`}
          >
            {t(PASSWORD_RULE)}
          </p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t("Cancel")}
          </Button>
          <Button onClick={submit} disabled={saving || passwordInvalid(password)}>
            {t("Save")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
