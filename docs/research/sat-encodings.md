# SAT Encodings (v4.0.0)

SHA-256 is an XOR-dominated circuit: every σ and γ function is a pure XOR, and
the adder sum bits are XORs with a carry. The choice of encoding therefore
matters more than the choice of solver.

## Dialects

### `tseitin` — pure CNF

Every gate becomes auxiliary variables plus clauses. Universally compatible
with CaDiCaL, Kissat, MiniSat, and Z3. The XOR of two literals costs 4 clauses
and one extra variable.

### `xor` — extended DIMACS with native XOR constraints

Emits CryptoMiniSat's `x <lits> 0` form so the solver can apply Gaussian
elimination over the GF(2) subsystem instead of clause-level unit propagation.
This is the single largest win on this circuit.

`CnfFormula::add_xor_constraint` normalises literals before emitting:

- A variable repeated an **odd** number of times contributes the variable
  (signed by the majority sign).
- A variable repeated an **even** number of times contributes nothing.
- Each **opposite-sign pair** contributes the constant 1, flipping the parity.

CryptoMiniSat XOR clauses have no negated form, so a false-parity constraint
absorbs the formula's shared `TRUE` literal rather than duplicating a literal
(XOR is self-cancelling, so duplicating one would *remove* it, not flip it).

The dialect is validated in `test_sat_dialect_semantic_equivalence`, which pins
reference inputs and the reference digest and checks the formula with unit
propagation before handing it to a solver.

## Carry-save multi-operand addition

`encode_add32_multi` reduces addends with **3:2 compressors**, which satisfy

```
a + b + c  ==  sum + 2 * carry
```

exactly, with `sum = a XOR b XOR c` and `carry = MAJ(a, b, c)`. Each column is
reduced to at most two literals, leaving two rows that one ripple-carry adder
finishes.

This is what makes `T1 = h + Σ1(e) + Ch(e,f,g) + W[t] + K[t]` collapse from four
serial ripple adders into a single pass.

> **Why not XOR the addends together?** Because that silently loses the column
> weight. `3 + 3` needs a carry of *two*, not a single bit, so a parity
> collapse would encode `3 + 3` as `0`. The multi-operand adder is covered by
> `test_sat_add32_multi_semantics`, which checks all combinations of small
> operands in both dialects precisely to catch this class of bug.

## Constant folding

`encode_add32_const` exploits that `K[t]` is a compile-time constant:

| Bit of `K` | Sum bit | Carry out |
| :--- | :--- | :--- |
| `0` | `a XOR carry` | `a AND carry` |
| `1` | `NOT(a XOR carry)` | `a OR carry` |

This avoids materialising a 32-variable constant word plus 32 unit clauses per
constant.

## Measured effect

At 17 rounds, from `reports/preimage_encoding_compare.md`:

| Configuration | CNF vars | CNF clauses | vs. baseline |
| :--- | ---: | ---: | :--- |
| `tseitin` / CaDiCaL | 21128 | 68552 | baseline |
| `tseitin+cs` / CaDiCaL | 20550 | 72171 | −3% vars |
| `xor` / CryptoMiniSat | 16616 | 29256 | −21% vars, −57% clauses |
| `xor+cs` / CryptoMiniSat | **15511** | 30835 | **−27% vars, −55% clauses** |

All four configurations produced an independently verified 17-round preimage.

## Usage

```bash
sha-research preimage --rounds 17 --solver cryptominisat --encoding xor --carry-save
sha-research preimage --rounds 17 --solver cadical --encoding tseitin
```

Combining `--encoding xor` with a non-XOR-capable solver is rejected up front
rather than silently producing a formula the solver will misparse.

## Result contract

Every run emits machine-readable lines:

```
RESULT_CANDIDATE=<path|NONE>
RESULT_TARGET_DIGEST=<64 hex>
RESULT_ROUNDS=<n>
RESULT_CLASSIFICATION=<name>
RESULT_CNF_VARS=<n>
RESULT_CNF_CLAUSES=<n>
RESULT_CNF_XORS=<n>
RESULT_ENCODING=<tseitin|xor>
RESULT_CARRY_SAVE=<0|1>
RESULT_ENCODE_TIME=<seconds>
RESULT_SOLVER_TIME=<seconds>
RESULT_SOLVER_STATUS=<SAT|UNSAT|TIMEOUT|ERROR|UNKNOWN>
RESULT_SOLVER_EXIT=<code>
```

The Python platform consumes these instead of scraping prose. Exit codes:
`0` independently verified, `1` no candidate, `2` verification failure or bad
configuration.