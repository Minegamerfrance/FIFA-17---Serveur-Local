STRATEGY RESET — Login freeze (28/07/2026 ~17:45)
==================================================

Objectif UX
-----------
Passer « connexion serveur » (mini freeze → splash → FAIL1 ~35s).

Carte A→Z (prouvé uniquement)
-----------------------------
1. Redirector + ProtoSSL + Fire2     OK
2. PreAuth Util/7                    OK
3. Origin gates (online/auth/ver)    OK → Auth/10 part
4. Auth/10 REPLY consommée error=0   OK (pas un bug TDF matching)
5. Corps TDF PLST/full/persona/none  ÉLIMINÉ pour le timer 30s
6. status.slots[] jamais remplis     BUG producteur manquant
   → STATUS_SLOT_POKE = contournement → Jobq READY, plus logout/70
7. LoginStateLogin switch(+0x260)    coincé case 2 (BUSY)
8. CNNS +0x6d4/+0x6e0                pas le gate busy (poke négatif)
9. LOGIN_STATE_POKE 2→0              rejoue gate → LoginCall 1×
   ret=0x18 → re-case 2 ; OBS_SUCC=0

Verdict
-------
Le pipeline Blaze/Auth marche. On est bloqué sur une **complétion async
manquante** de la Login SM, pas sur « encore un flag à poke ».

Les pokes prouvent que les portes sont atteignables ; ils ne créent pas
le signal qui écrit `+0x260 → 5` (case SUCC @0x71b5c71).

Machine d’états (statique)
--------------------------
  case 0 GATE → lookup ; NULL→LoginCall/ebmg ; sinon vt+0…
  LoginCall path : `+0x260:=1` puis call 0x717d5d0
  case 1 @0x71b5c0d → tombe sur store `+0x260:=2` (entrer en attente)
  case 2 @0x71b5c43 → poll timeout → FAIL1
  case 5 @0x71b5c71 → SUCC : `+0x260:=6`, cnns+0x6d0:=1, +0x264:=5
  → Quelque chose d’EXTERNE doit poser `+0x260=5` (ou jmp SUCC).
    LoginCall ret=0x18 ≠ SUCC.

Pourquoi on tournait en rond
----------------------------
Pattern : trouver un champ à 0 → poke → prochaine porte → poke…
Chaque poke masque un producteur natif mort (slots, ready flags, state).
Ça cartographie ; ça ne fixe pas la cause.

Interdit (jusqu’à signal réel)
------------------------------
- Nouveau poke (state / cnns / slot / vt)
- A/B TDF Auth aveugle
- Mid-fn Interceptor dans LoginStateLogin
- Stalker / softHost / SetState

UNE seule prochaine expérience
------------------------------
Q : Qui écrit `login+0x260` avec une valeur ≠ 2 (surtout 5) ?
    OU : après LoginCall, quel callback/event devrait avancer la SM ?

Méthode (au choix, pas les deux en même temps) :
  A) MAM WRITE court sur `login+0x260` (4 octets), pokes OFF sauf
     STATUS_SLOT si nécessaire pour rester hors logout — log writer RVA
     + valeur. Succès = voir un writer vers 5, ou prouver 0 writer ≠2.
  B) Disasm/trace LoginCall 0x717d5d0 seul : sens de ret=0x18 + ce qu’il
     arme (job, waiter, ebisu). Succès = nommer l’événement attendu.

Critère d’arrêt poke : si A montre aucun writer vers 5 pendant 35s,
le levier n’est PAS dans LoginStateLogin — chercher Origin/Ebisu/Nucleus
callback / notif Blaze post-Auth qui aurait dû armer ce writer.

Implémenté (strategy A)
-----------------------
- PIPE_LOGIN_260_MAM=1 (défaut) : MAM WRITE observe-only sur login+0x260
- PIPE_STATUS_SLOT_POKE / CNNS_READY_POKE / LOGIN_STATE_POKE = 0 (défaut)
- Log : `LOGIN_260_MAM #n ★TO_X old→new rip=… regs…` + `LOGIN_260_MAM_BT`
- Décisif : `LOGIN_260_HIT_SUCC5` OU `hit5=0` à la fin du freeze

Retest :
  $env:PIPE_ORIGIN_ONLINE_FIX="1"
  $env:PIPE_ORIGIN_AUTHCODE_FIX="1"
  $env:PIPE_ORIGIN_VERSION_FIX="1"
  $env:PIPE_EBISU_FIX="1"
  # pokes déjà OFF ; MAM déjà ON
  .\tools\run-pipeline-probe.ps1
+ npm run start:auth-origin-layer

Chercher : `LOGIN_260_MAM`, `LOGIN_260_HIT_SUCC5`, `LOGIN_260_MAM disabled`
