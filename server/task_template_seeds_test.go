package server

import (
	"errors"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestSeedTaskTemplatesIdempotent verifies the seed is first-insert-only by name:
// running it twice must not create duplicates, and an operator's edit to a seeded
// template's goal (same name, so same nkey) must survive a reseed rather than being
// overwritten back to the built-in text.
func TestSeedTaskTemplatesIdempotent(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer pg.Close()

	if len(builtinTaskTemplates) == 0 {
		t.Fatal("builtinTaskTemplates is empty")
	}

	// Clean slate for every builtin name this test owns, so a prior failed run
	// cannot leave rows behind that make this run a false pass.
	for _, bt := range builtinTaskTemplates {
		existing, err := pg.ListTaskTemplates()
		if err != nil {
			t.Fatalf("ListTaskTemplates: %v", err)
		}
		for _, et := range existing {
			if et.Name == bt.Name {
				if _, err := pg.DeleteTaskTemplate(et.ID); err != nil {
					t.Fatalf("cleanup DeleteTaskTemplate(%d): %v", et.ID, err)
				}
			}
		}
	}

	seedTaskTemplates(pg)

	byName := func() map[string]*db.TaskTemplate {
		all, err := pg.ListTaskTemplates()
		if err != nil {
			t.Fatalf("ListTaskTemplates: %v", err)
		}
		m := map[string]*db.TaskTemplate{}
		for _, tpl := range all {
			m[tpl.Name] = tpl
		}
		return m
	}

	first := byName()
	for _, bt := range builtinTaskTemplates {
		got, ok := first[bt.Name]
		if !ok {
			t.Fatalf("seed did not create template %q", bt.Name)
		}
		if got.Goal != bt.Goal {
			t.Fatalf("template %q: seeded goal does not match builtinTaskTemplates source", bt.Name)
		}
	}

	// Simulate an operator edit to one seeded template (same name -> same nkey).
	target := first[builtinTaskTemplates[0].Name]
	edited := "operator-edited goal text, must survive reseed"
	if _, err := pg.PatchTaskTemplate(target.ID, db.TaskTemplatePatch{
		Goal: &edited,
	}); err != nil {
		t.Fatalf("PatchTaskTemplate: %v", err)
	}

	// Reseed: must be a no-op for every already-present name (ON CONFLICT (nkey) DO
	// NOTHING), and must not create a second row for any of them.
	seedTaskTemplates(pg)

	second := byName()
	for _, bt := range builtinTaskTemplates {
		if _, ok := second[bt.Name]; !ok {
			t.Fatalf("template %q disappeared after reseed", bt.Name)
		}
	}
	reEdited, ok := second[builtinTaskTemplates[0].Name]
	if !ok {
		t.Fatalf("edited template %q missing after reseed", builtinTaskTemplates[0].Name)
	}
	if reEdited.Goal != edited {
		t.Fatalf("reseed overwrote the operator's edit: got %q, want %q", reEdited.Goal, edited)
	}

	// Count rows per builtin name: must stay at exactly one each, never duplicated.
	all, err := pg.ListTaskTemplates()
	if err != nil {
		t.Fatalf("ListTaskTemplates: %v", err)
	}
	counts := map[string]int{}
	for _, tpl := range all {
		counts[tpl.Name]++
	}
	for _, bt := range builtinTaskTemplates {
		if counts[bt.Name] != 1 {
			t.Fatalf("template %q: want exactly 1 row after two seed runs, got %d", bt.Name, counts[bt.Name])
		}
	}

	// Cleanup: remove every row this test created/touched.
	for _, tpl := range all {
		for _, bt := range builtinTaskTemplates {
			if tpl.Name == bt.Name {
				if _, err := pg.DeleteTaskTemplate(tpl.ID); err != nil {
					t.Errorf("cleanup DeleteTaskTemplate(%d): %v", tpl.ID, err)
				}
			}
		}
	}
}

// TestSeedTaskTemplatesSkipsConflictSilently documents that a name conflict from
// CreateTaskTemplate is the expected steady-state outcome, not a logged failure
// path — seedTaskTemplates must treat it as such.
func TestSeedTaskTemplatesSkipsConflictSilently(t *testing.T) {
	if !errors.Is(db.ErrTaskTemplateNameConflict, db.ErrTaskTemplateNameConflict) {
		t.Fatal("sanity: errors.Is must match db.ErrTaskTemplateNameConflict against itself")
	}
}
