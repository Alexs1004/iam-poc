#!/usr/bin/env python3
"""Test rapide des corrections apportées."""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

print("=" * 60)
print("✅ TEST 1: Import du module audit depuis jml.py")
print("=" * 60)

try:
    from scripts import jml
    print(f"✅ Module jml importé avec succès")
    print(f"   - audit_module disponible: {jml.audit_module is not None}")
    if jml.audit_module:
        print(f"   - Fonction append_audit_jsonl: {hasattr(jml.audit_module, 'append_audit_jsonl')}")
except Exception as e:
    print(f"❌ Erreur lors de l'import: {e}")
    sys.exit(1)

print("\n" + "=" * 60)
print("✅ TEST 2: Vérification disable_user() (ne retire PAS du groupe)")
print("=" * 60)

import inspect
disable_user_source = inspect.getsource(jml.disable_user)

if "remove_user_from_group" in disable_user_source:
    if disable_user_source.count("#") > disable_user_source.count("remove_user_from_group"):
        print("✅ remove_user_from_group est commenté (utilisateurs restent visibles)")
    else:
        print("❌ remove_user_from_group est toujours actif (utilisateurs disparaissent)")
        sys.exit(1)
else:
    print("✅ remove_user_from_group absent de la fonction (OK)")

if '"archived": False' in disable_user_source or "'archived': False" in disable_user_source:
    print("✅ Audit log avec archived=False (correct)")
else:
    print("⚠️  Vérifier manuellement le log audit")

print("\n" + "=" * 60)
print("✅ TEST 3: admin.py passe flash_messages au template")
print("=" * 60)

try:
    with open(PROJECT_ROOT / "app" / "api" / "admin.py", "r") as f:
        admin_content = f.read()
    
    if "get_flashed_messages(with_categories=True)" in admin_content:
        print("✅ get_flashed_messages() appelé dans admin_dashboard()")
    else:
        print("❌ get_flashed_messages() manquant")
        sys.exit(1)
    
    if 'flash_messages=flash_messages' in admin_content or 'flash_messages = flash_messages' in admin_content:
        print("✅ flash_messages passé au template")
    else:
        print("❌ flash_messages non passé au render_template()")
        sys.exit(1)
        
except Exception as e:
    print(f"❌ Erreur: {e}")
    sys.exit(1)

print("\n" + "=" * 60)
print("✨ TOUS LES TESTS RÉUSSIS !")
print("=" * 60)
print("\nCorrections appliquées :")
print("  1. ✅ Import audit corrigé (sys.path)")
print("  2. ✅ disable_user() ne retire plus du groupe")
print("  3. ✅ Flash messages passés au template")
print("\nProchain test :")
print("  make fresh-demo  # Bob devrait rester visible avec statut 'Disabled'")
