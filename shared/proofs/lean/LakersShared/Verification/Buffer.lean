module
public import Aeneas
public import CoreModels
public import LakersShared.Extraction.Types
public import LakersShared.Extraction.Funs
public import LakersShared.Extraction.Specs
@[expose] public section
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option linter.style.whitespace false
set_option linter.style.setOption false
set_option linter.style.longLine false
set_option linter.internalConstructors false

/- You can set the `maxHeartbeats` value with the `-max-heartbeats` CLI option -/
set_option maxHeartbeats 1000000

/- You can set the `maxRecDepth` value with the `-max-recdepth` CLI option -/
set_option maxRecDepth 2048

/- You can remove the following line by using the CLI option `-all-computable`: -/
noncomputable section

namespace lakers_shared

-- SPECS TO HELP PROVE START
@[spec]
theorem buffer.copy_into_longer_loop.spec (long short : Slice Std.U8) (cursor : Std.Usize)
    (h1 : cursor.val ≤ short.val.length) (h2 : short.val.length ≤ long.val.length) :
    ⦃ ⌜ True ⌝ ⦄ buffer.copy_into_longer_loop long short cursor
    ⦃ ⇓ res => ⌜ res.val.length = long.val.length ⌝ ⦄ := by
  unfold buffer.copy_into_longer_loop
  apply loop_spec
    (inv := fun (p : Slice Std.U8 × Std.Usize) =>
      p.2.val ≤ short.val.length ∧ p.1.val.length = long.val.length)
    (rel := (· < ·)) (termination := fun p => p.2.val) (hwf := wellFounded_lt)
  · exact ⟨h1, rfl⟩
  · intro x hx
    obtain ⟨l, c⟩ := x
    unfold buffer.copy_into_longer_loop.body
    hax_mvcgen
    all_goals grind

-- cloning a u8 is just ok self, so cloning a whole list returns the same list.
theorem u8_clone_mapM (l : List Std.U8) :
    l.mapM core.U8.Insts.CoreCloneClone.clone = ok l := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.mapM_cons, ih, core.U8.Insts.CoreCloneClone.clone, bind_tc_ok]
    rfl

-- the sequence is exactly replicate n x, and scalar_tac proves its length fits in a usize (it's n, which is already a usize).
theorem u8_seq_create (x : Std.U8) (n : Std.Usize) :
    ∃ s, rust_primitives.sequence.seq_create core.U8.Insts.CoreCloneClone x n = ok s
      ∧ s.val = List.replicate n.val x := by
  unfold rust_primitives.sequence.seq_create
  by_cases h0 : n.val = 0
  · exact ⟨Slice.new _, by simp [h0], by simp [h0, Slice.new_val]⟩
  · simp only [h0, ite_false, u8_clone_mapM, RustM.match.ok]
    have hl : (List.replicate (n.val - 1) x ++ [x]).length ≤ Usize.max := by
      simp only [List.length_append, List.length_replicate, List.length_singleton]
      scalar_tac
    simp only [hl, _root_.dite_true]
    refine ⟨_, rfl, ?_⟩
    simp only [Slice.from_val, ← List.replicate_succ']
    congr 1; omega

-- Calling go n times on a sequence of length n + k returns n copies and leaves a sequence of length k. The induction has to generalize k. The recursive call runs first, so it needs one extra element left over (k + 1) for the current call's seq_remove to succeed. That leftover element is the proof that seq_remove never panics.
theorem u8_repeat_go (N : Std.Usize) (x : Std.U8) (n k : Nat)
    (s : rust_primitives.sequence.Seq Std.U8) (hs : s.val = List.replicate (n + k) x) :
    ∃ s' : rust_primitives.sequence.Seq Std.U8,
      rust_primitives.slice.array_from_fn_go
        (core.array.repeat.closure.Insts.CoreOpsFunctionFnMutTupleUsizeT N
          core.U8.Insts.CoreCloneClone) s n = ok (List.replicate n x, s')
      ∧ s'.val = List.replicate k x := by
  induction n generalizing k with
  | zero => exact ⟨s, rfl, by simpa using hs⟩
  | succ n ih =>
    obtain ⟨s1, h1, hs1⟩ := ih (k + 1) (by rw [hs]; congr 1; omega)
    unfold rust_primitives.slice.array_from_fn_go
    rw [h1, bind_ok]
    have hlen : 0 < s1.val.length := by simp [hs1]
    refine ⟨Slice.from (s1.val.take 0 ++ s1.val.drop 1) (by have := s1.property; simp; omega), ?_, ?_⟩
    · show (do
          let q ← rust_primitives.sequence.seq_remove s1 0#usize >>= fun (t, s) => ok (t, s)
          ok (List.replicate n x ++ [q.1], q.2)) = _
      unfold rust_primitives.sequence.seq_remove
      have hlen' : (0#usize : Std.Usize).val < s1.val.length := by simpa using hlen
      simp only [hlen', ↓reduceDIte]
      simp only [bind_tc_ok]
      have hhead : s1.val.get ⟨(0#usize : Std.Usize).val, hlen'⟩ = x := by
        simp [hs1]
      rw [hhead, List.replicate_succ']
      rfl
    · simp [hs1]

-- The final length check is true because (replicate N x).length = N. With @[spec] on it, your hax_mvcgen calls for new and default now pick it up automatically.
@[spec]
theorem u8_array_repeat_spec (N : Std.Usize) (x : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
    core.array.repeat N core.U8.Insts.CoreCloneClone x
    ⦃ ⇓ a => ⌜ a.val = List.replicate N.val x ⌝ ⦄ := by
  obtain ⟨s, hc, hsv⟩ := u8_seq_create x N
  obtain ⟨s', hg, _⟩ := u8_repeat_go N x N.val 0 s (by simpa using hsv)
  unfold core.array.repeat rust_primitives.slice.array_from_fn
  simp only [hc, bind_ok]
  simp only [hg, bind_ok, List.length_replicate, ↓reduceDIte]
  hax_mvcgen
  simp [Array.from_val]
-- SPECS TO HELP PROVE END

theorem buffer.copy_into_longer.spec.proof (long : Slice Std.U8)
  (short : Slice Std.U8) : buffer.copy_into_longer.spec long short
  := by
  unfold buffer.copy_into_longer.spec buffer.copy_into_longer
  hax_mvcgen [core.slice.Slice.len]
  all_goals grind

theorem
  buffer.LakeBuffer.Insts.CoreDefaultDefault.default.spec.proof (N : Std.Usize)
  : buffer.LakeBuffer.Insts.CoreDefaultDefault.default.spec N
  := by
  unfold buffer.LakeBuffer.Insts.CoreDefaultDefault.default.spec buffer.LakeBuffer.Insts.CoreDefaultDefault.default
  hax_mvcgen

theorem buffer.LakeBuffer.new.spec.proof (N : Std.Usize) :
  buffer.LakeBuffer.new.spec N
  := by
  unfold buffer.LakeBuffer.new.spec buffer.LakeBuffer.new
  hax_mvcgen

theorem buffer.LakeBuffer.invariant.spec.proof {N : Std.Usize}
  (self : buffer.LakeBuffer N) : buffer.LakeBuffer.invariant.spec self
  := by
  unfold buffer.LakeBuffer.invariant.spec buffer.LakeBuffer.invariant
  hax_mvcgen

theorem buffer.LakeBuffer.impl.len.spec.proof {N : Std.Usize}
  (self : buffer.LakeBuffer N) : buffer.LakeBuffer.impl.len.spec self
  := by
  unfold buffer.LakeBuffer.impl.len.spec buffer.LakeBuffer.impl.len
  hax_mvcgen

theorem buffer.LakeBuffer.capacity.spec.proof {N : Std.Usize}
  (self : buffer.LakeBuffer N) : buffer.LakeBuffer.capacity.spec self
  := by
  unfold buffer.LakeBuffer.capacity.spec buffer.LakeBuffer.capacity
  hax_mvcgen

end lakers_shared
