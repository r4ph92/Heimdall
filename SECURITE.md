# Sécurité de Heimdall — Documentation complète

Ce document explique, partie par partie, comment la sécurité est implémentée dans Heimdall. L'objectif est de comprendre le *pourquoi* derrière chaque décision, pas seulement le *quoi*.

---

## 1. Le principe fondamental : zéro connaissance (Zero-Knowledge)

Heimdall est conçu selon le principe **zéro connaissance** : le serveur ne connaît jamais ton mot de passe maître ni la clé de chiffrement de ton coffre. Même si la base de données était volée intégralement, les mots de passe dans le coffre seraient illisibles.

Ce principe se résume ainsi :
> Le serveur stocke uniquement du **texte chiffré**. La clé pour déchiffrer n'existe que dans ta session, dérivée à partir de ton mot de passe maître que toi seul connais.

Si tu perds ton mot de passe maître, ton coffre est **irrécupérable par design** — même par l'administrateur du serveur. Ce n'est pas un bug, c'est une garantie de sécurité.

---

## 2. Inscription (création de compte)

### Ce qui se passe quand tu crées un compte

1. Tu entres ton nom, courriel et mot de passe maître
2. Le mot de passe est **haché avec bcrypt** (Laravel `Hash::make()`) avant d'être enregistré dans la base de données
3. Un **sel de coffre** (`vault_salt`) est généré aléatoirement : `random_bytes(32)` encodé en base64
4. Ce sel est stocké en clair dans la base de données — c'est voulu, on y reviendra

### Pourquoi hacher le mot de passe ?

Le hachage est une fonction à sens unique. Si la base de données est compromise, l'attaquant voit `$2y$12$...` (le hash bcrypt), pas ton mot de passe. Bcrypt est intentionnellement lent à calculer, ce qui rend les attaques par force brute coûteuses.

### Pourquoi un sel de coffre séparé ?

Le `vault_salt` sert à **dériver la clé de chiffrement** (expliqué à la section 3). Il est différent du sel interne à bcrypt. Le fait qu'il soit en clair dans la base de données est normal : sans le mot de passe maître, le sel seul est inutile — comme avoir le verrou d'un coffre-fort sans la combinaison.

### Ce que la base de données contient après l'inscription

| Colonne | Valeur | Sensible ? |
|---|---|---|
| `email` | ton courriel | Oui, mais pas un secret cryptographique |
| `password` | hash bcrypt | Oui — ne peut pas retrouver le mot de passe original |
| `vault_salt` | sel aléatoire base64 | Non — inutile sans le mot de passe maître |

---

## 3. Connexion et dérivation de la clé

### Ce qui se passe quand tu te connectes

1. Tu entres ton courriel et ton mot de passe maître
2. Laravel vérifie le mot de passe contre le hash bcrypt en base de données
3. Si correct → **dérivation de la clé de chiffrement** via PBKDF2
4. La clé dérivée est stockée **uniquement dans la session**, jamais en base de données
5. La session est régénérée (nouvel identifiant) pour prévenir la fixation de session

### PBKDF2 : comment la clé est dérivée

```
clé = PBKDF2-SHA256(mot_de_passe_maître, vault_salt, 200 000 itérations, 32 octets)
```

**PBKDF2** (Password-Based Key Derivation Function 2) transforme un mot de passe humain en une clé cryptographique de 256 bits. Les paramètres importants :

- **SHA-256** : l'algorithme de hachage utilisé en interne
- **200 000 itérations** : recommandation minimale de l'OWASP pour 2024. Chaque itération recalcule le hash, donc l'opération prend ~200ms. Pour un humain, c'est imperceptible. Pour un attaquant qui teste des millions de mots de passe, c'est prohibitif.
- **32 octets** : la clé résultante fait 256 bits, ce qui correspond à AES-256

La clé est ensuite encodée en base64 et stockée dans `session('vault_key')`.

### Pourquoi la clé n'est-elle pas en base de données ?

Parce que si elle l'était, quelqu'un ayant accès à la base de données pourrait déchiffrer tous les coffres directement. En la gardant uniquement en session (mémoire serveur), on garantit que même un dump complet de la base de données ne compromet pas les coffres.

---

## 4. Chiffrement du coffre (AES-256-GCM)

### L'algorithme : AES-256-GCM

Quand tu ajoutes ou modifies une entrée, le mot de passe (et les notes) sont chiffrés avec **AES-256-GCM** avant d'être enregistrés.

- **AES** (Advanced Encryption Standard) : standard mondial de chiffrement symétrique
- **256** : taille de la clé en bits — le niveau le plus élevé d'AES
- **GCM** (Galois/Counter Mode) : mode qui combine chiffrement **et** authentification

### Pourquoi GCM et pas juste AES ?

GCM produit une **étiquette d'authentification** (auth tag) de 16 octets en plus du texte chiffré. Cette étiquette permet de détecter toute modification du texte chiffré — si quelqu'un altère la base de données, le déchiffrement échoue au lieu de retourner des données corrompues silencieusement.

AES sans GCM (ex: AES-CBC) ne garantit pas l'intégrité : un attaquant pourrait modifier des octets du chiffré et tu obtiendrais des données corrompues sans le savoir.

### Le vecteur d'initialisation (IV)

Chaque chiffrement génère un **IV aléatoire de 12 octets** via `random_bytes(12)`.

```
texte_chiffré + étiquette = AES-256-GCM(plaintext, clé, IV)
```

L'IV est stocké en clair en base de données à côté du texte chiffré — c'est normal et nécessaire pour déchiffrer. Sa seule contrainte : **ne jamais réutiliser le même IV avec la même clé**.

### Pourquoi ne pas réutiliser un IV ?

AES-GCM est un chiffrement par flux (stream cipher). Si tu chiffres deux messages différents avec la même clé et le même IV, un attaquant peut faire le XOR des deux textes chiffrés et annuler le flux de clé, récupérant ainsi le XOR des deux plaintexts. En pratique, ça révèle les données.

C'est pourquoi lors de la **modification** d'une entrée, un nouvel IV est toujours généré — même si le mot de passe n'a pas changé.

### Ce que la base de données contient pour une entrée

| Colonne | Valeur | Peut être lu sans la clé ? |
|---|---|---|
| `service_name` | "GitHub" | Oui — métadonnée en clair |
| `username` | "toi@exemple.com" | Oui — métadonnée en clair |
| `url` | "https://github.com" | Oui — métadonnée en clair |
| `encrypted_password` | texte chiffré + auth tag (base64) | Non |
| `iv` | vecteur d'initialisation (base64) | Oui — nécessaire pour déchiffrer, mais inutile sans la clé |
| `encrypted_notes` | texte chiffré des notes (base64) | Non |
| `notes_iv` | IV des notes | Oui |

Note : le nom du service, le nom d'utilisateur et l'URL sont en clair. Seuls le mot de passe et les notes sont chiffrés. C'est un compromis de conception — chiffrer tout rendrait la recherche impossible côté serveur.

---

## 5. Authentification à deux facteurs (2FA/MFA)

La 2FA ajoute une deuxième couche après le mot de passe maître. Même si quelqu'un connaît ton mot de passe, il ne peut pas accéder au coffre sans le deuxième facteur.

### Méthode 1 : Code par courriel (Email OTP)

1. Après connexion réussie, un code à 6 chiffres aléatoires est généré
2. Il est mis en cache côté serveur pendant **10 minutes** maximum
3. Il est envoyé par courriel
4. Il n'est valide qu'**une seule fois** — après utilisation, il est supprimé du cache

### Méthode 2 : Application d'authentification (TOTP)

TOTP (Time-based One-Time Password) est le standard derrière Google Authenticator, Authy, etc.

1. Un secret est généré et stocké dans la base de données (champ `two_factor_secret`)
2. Un QR code est affiché à l'écran pour scanner avec l'app
3. L'app et le serveur calculent indépendamment un code à 6 chiffres à partir du secret + l'heure actuelle (fenêtres de 30 secondes)
4. Si les deux codes correspondent, l'identité est confirmée

Le secret TOTP est stocké en base de données. Si la base de données est compromise, un attaquant ayant le secret TOTP peut générer des codes valides — c'est pourquoi le mot de passe maître reste la première ligne de défense.

### Codes de récupération

À l'activation du 2FA, 8 codes de récupération sont générés. Ils permettent de contourner le 2FA si tu perds accès à ton courriel ou ton application.

- Ils sont affichés **une seule fois**
- Côté serveur, seuls leurs **hashes bcrypt** sont stockés — jamais les codes en clair
- Chaque code est **à usage unique** : il est invalidé après utilisation

### Middleware : la chaîne de protection

Chaque route du coffre passe par trois vérifications dans l'ordre :

```
1. auth                      → es-tu connecté ?
2. EnsureVaultKeyInSession   → la clé de chiffrement est-elle en session ?
3. EnsureMfaVerified         → as-tu complété le défi 2FA cette session ?
```

Si la session expire (redémarrage serveur, timeout), la clé de chiffrement disparaît. Le middleware `EnsureVaultKeyInSession` détecte ça et force une reconnexion complète pour re-dériver la clé. C'est intentionnel.

---

## 6. Limitation des tentatives de connexion (Rate Limiting)

Pour prévenir les attaques par force brute sur le mot de passe maître :

- **10 tentatives maximum par minute** par combinaison courriel + adresse IP
- Au-delà, le compte est bloqué temporairement et un message indique combien de secondes attendre
- En cas de succès, le compteur est remis à zéro

La clé de limitation combine courriel **et** IP pour deux raisons :
- Quelqu'un ciblant un compte spécifique depuis une seule IP est bloqué
- Quelqu'un changeant d'IP pour cibler un compte est aussi bloqué (par courriel)
- Un utilisateur légitime faisant des fautes de frappe n'est pas bloqué sur d'autres comptes

---

## 7. Changement du mot de passe maître

Changer le mot de passe maître est l'opération la plus délicate du système.

### Pourquoi c'est complexe

La clé de chiffrement est dérivée du mot de passe maître. Changer le mot de passe signifie que la nouvelle clé sera différente. Il faut donc **re-chiffrer tout le coffre** avec la nouvelle clé.

### Ce qui se passe concrètement

1. L'ancien mot de passe est vérifié
2. La clé actuelle est récupérée depuis la session
3. Un **nouveau sel** est généré (`vault_salt`)
4. La nouvelle clé est dérivée via PBKDF2 (nouveau mot de passe + nouveau sel)
5. Chaque entrée du coffre est déchiffrée avec l'ancienne clé, puis re-chiffrée avec la nouvelle (avec un nouvel IV à chaque fois)
6. La base de données est mise à jour en bloc
7. La session est mise à jour avec la nouvelle clé

Si le processus échoue à mi-chemin, certaines entrées pourraient être corrompues. Une implémentation robuste ferait ça dans une transaction de base de données — c'est un point d'amélioration possible.

---

## 8. Audit de sécurité

L'audit analyse les mots de passe du coffre sans jamais les stocker en dehors du processus d'analyse.

### Calcul d'entropie

L'entropie mesure la force d'un mot de passe en bits :

```
entropie = longueur × log2(taille_de_l_alphabet)
```

L'alphabet grandit selon les types de caractères présents :
- Minuscules : +26
- Majuscules : +26
- Chiffres : +10
- Caractères spéciaux : +32

Un mot de passe de 12 caractères avec tout les types donne environ 78 bits — considéré fort.

### Détection de réutilisation

Comparer les mots de passe en clair entre entrées poserait un problème si ces données fuitaient. À la place, un **empreinte SHA-256** est calculée pour chaque mot de passe pendant l'audit :

```
empreinte = SHA-256(mot_de_passe)
```

Deux entrées avec la même empreinte ont le même mot de passe. L'empreinte ne permet pas de retrouver le mot de passe original, mais permet la comparaison. Ces empreintes ne sont jamais stockées — elles existent uniquement le temps de l'analyse en mémoire.

---

## 9. Gestion des sessions

- La table `sessions` stocke les sessions actives en base de données
- La clé de chiffrement (`vault_key`) et le flag MFA (`mfa_verified`) sont stockés dans le payload chiffré de la session
- Tu peux voir et révoquer tes sessions actives depuis les paramètres
- La révocation supprime directement la ligne en base de données, déconnectant l'appareil immédiatement

---

## 10. Résumé — Ce que le serveur ne peut PAS faire

Même avec un accès complet à la base de données et au code source, le serveur **ne peut pas** :

- Lire tes mots de passe stockés dans le coffre
- Retrouver ton mot de passe maître à partir du hash bcrypt
- Dériver ta clé de chiffrement sans ton mot de passe maître
- Accéder à ton coffre si ta session est expirée

C'est la garantie fondamentale du design zéro connaissance.
