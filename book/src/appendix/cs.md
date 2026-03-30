# Bootle16 v.s. R1CS

We demonstrate how to build Bootle16 CS and R1CS for the same toy arithmetic 
circuit with 2 `mul` gates and 1 `add` gate (but slightly different wire
labeling).
The output wire at the top is set as the only public output $x\in\F$.

Notice that the `mul` gate with a constant `4` input is a _scalar_ gate and not
counted as a `mul` gate since it doesn't require a dedicated gate
to check the wire values.
This distinction gives rise to the definition of 
**allocated wires** (input/output wires of `mul` gates) and 
**virtual wires** (I/O wires of `add` and `scalar` gates, usually serve as 
intermediate values for other allocated wires). As we will see below, 
gate relations for `add` and `scalar` are checked in the constraints as
part of a linear combination relationship between allocated wires.

<p align="center">
  <img src="../assets/bootle16_cs.svg" alt="example_circuit" />
</p>

Under Bootle16 CS, define witness vectors 
$\v{a}=(a_1, a_2), \v{b}=(b_1,b_2), \v{c}=(c_1, c_2)$, 
the circuit above necessitates the following checks:

- $\v{a}_i \cdot \v{b}_i = \v{c}_i$ for $i\in[2]$
- $\v{a}_2=4\v{b}_1+\v{c}_1 \land \v{b}_2=4\v{b}_1 \land \v{c}_2=\v{k}_1$: 
this translates to 3 constraint checks, 2 for circuit wiring, 1 for public input:
  - $\v{u}_1=(0, 1), \v{v}_1=(-4, 0), \v{w}_1=(0, -1), \v{k}_1=0$
  - $\v{u}_2=(0, 0), \v{v}_2=(4, -1), \v{w}_2=(0, 0), \v{k}_2=0$
  - $\v{u}_3=(0, 0), \v{v}_3=(4, -1), \v{w}_3=(0, 1), \v{k}_3=x_1$

Recall that in the standard R1CS, there exists a vector
$\v{z}=(1, \v{x}, \v{w})$
for the three public matrix $A, B, C$ describing the circuit such that 
$A\v{z} \circ B\v{z}=C\v{z}$.
In our case, $\v{z}=(1,x_1, w_1, w_2, w_3)\in\F^5$, and since there are two
multiplication gates (Hadamard checks), the matrices have two rows:
$A, B, C\in\F^{2\times 5}$. The constraints are encoded separately
via the $\v{u}, \v{v}, \v{w}, \v{k}$ vectors above. The matrices are:

$$
A=\begin{bmatrix}
   0 & 0 & 1 & 0 & 0 \\
   0 & 0 & 0 & 4 & 1
\end{bmatrix}
,\quad
B = \begin{bmatrix}
   0 & 0 & 0 & 1 & 0 \\
   0 & 0 & 0 & 4 & 0
\end{bmatrix}
,\quad
C = \begin{bmatrix}
   0 & 0 & 0 & 0 & 1 \\
   0 & 1 & 0 & 0 & 0
\end{bmatrix}
$$

As we can see, R1CS is (sometimes) slightly more compact in the sense that it
"squeezes" more constraint checks in a single row -- the second rows of $A, B, C$ does
a constraint check for the left, right, and public input wire respectively.

## Bootle16 to R1CS

The foregoing toy example should provide intuition of why Bootle16 and R1CS are 
equally powerful. Here we provide a generic transformation from Bootle16 to
R1CS,
and provide hints for the other direction.

Given the Bootle16 CS, let $\v{z}=(\v{a}\|\v{b}\|\v{c}\|\v{k})$, ignoring
padding issues, then define matrices $A, B, C\in\F^{(n+q)\times (3n+q)}$as:

$$
A=\begin{bmatrix}
   (1,0,\ldots) & \v{0} & \v{0} & \v{0}\\
   (0,1,\ldots) & \v{0} & \v{0} & \v{0}\\
   &&\ldots\\
   \v{u}_0 & \v{0} & \v{0} & (-1,0,\ldots)\\
   \v{u}_1 & \v{0} & \v{0} & (0,-1,\ldots)\\
   &&\ldots
\end{bmatrix}
,
B = \begin{bmatrix}
   \v{0} & (1,0,\ldots) & \v{0} & \v{0}\\
   \v{0} & (0,1,\ldots) & \v{0} & \v{0}\\
   &\ldots\\
   \v{0} & \v{v}_0 & \v{0} & \v{0}\\
   \v{0} & \v{v}_1 & \v{0} & \v{0}\\
   &\ldots
\end{bmatrix}
,
C = \begin{bmatrix}
   \v{0} & \v{0} & (1,0,\ldots) & \v{0}\\
   \v{0} & \v{0} & (0,1,\ldots) & \v{0}\\
   &&\ldots\\
   \v{0} & \v{0} & \v{w}_0 & \v{0}\\
   \v{0} & \v{0} & \v{w}_1 & \v{0}\\
   &&\ldots
\end{bmatrix}
$$

It's not hard to verify yourself that the first $n$ rows enforce the gate
equations, and the last $q$ enforce the constraints.
This transformation is perfectly complete and sound, but usually wasteful.

Now, to see the connection from the other direction (R1CS to Bootle16),
let $\v{z}_A = Az, \v{z}_B=Bz, \v{z}_C=Cz$, since the final
$\v{z}_A \circ \v{z}_B=\v{z}_C$ is doing the $n$ Hadamard checks, we know
$\v{a}=\v{z}_A,\v{b}=\v{z}_B, \v{c}=\v{z}_C$. 
However, extrapolating what $A, B, C$ demands into Bootle16's linear relation
among the three witness vectors is a little hairy, but can be done with a
generic
and deterministic algorithm (we skip the details here).
