Dossier versions — logs de test ProtoSSL / Frida
================================================

Chaque version a un sous-dossier:
  tools/versions/vNN/
    NOTES.txt   = ce que change cette version + hypothèse
    frida.log   = sortie de run-ssl-bypass.ps1 (auto)
    npm.log     = sortie de npm start (via run-npm-logged.ps1)

Fichier CURRENT.txt = version active (ex: v29).

Comment tester demain
---------------------
1) Éditer CURRENT.txt si besoin (ex: v29)
2) Fenêtre 1:
     powershell -ExecutionPolicy Bypass -File tools\run-npm-logged.ps1
3) Lancer FIFA (menu principal)
4) Fenêtre 2:
     powershell -ExecutionPolicy Bypass -File tools\run-ssl-bypass.ps1
5) Entrer en UT — NE PAS Ctrl+C sur Frida
6) Quand fini: Ctrl+C dans les 2 fenêtres
7) Dire à Cursor: "lis tools/versions/v29/" — plus besoin de coller les logs

Nouvelle version
----------------
1) Copier le dossier vNN → vNN+1
2) Mettre à jour NOTES.txt
3) Vider frida.log et npm.log (ou les laisser écraser)
4) Mettre CURRENT.txt = vNN+1
