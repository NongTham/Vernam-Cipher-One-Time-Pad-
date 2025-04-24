import secrets
import os

def generate_key(length: int) -> bytes:
  if length <= 0:
      raise ValueError("ความยาวกุญแจต้องมากกว่า 0")
  return secrets.token_bytes(length)

def process_data(data: bytes, key: bytes) -> bytes:
  if len(key) < len(data):
    raise ValueError("ข้อผิดพลาด: กุญแจต้องมีความยาวอย่างน้อยเท่ากับข้อมูล")

  processed = bytearray()
  for i in range(len(data)):
    processed.append(data[i] ^ key[i])
  return bytes(processed)

def read_file_bytes(filepath: str) -> bytes:
  try:
    with open(filepath, 'rb') as f:
      return f.read()
  except FileNotFoundError:
    print(f"ข้อผิดพลาด: ไม่พบไฟล์ '{filepath}'")
    return None
  except Exception as e:
    print(f"ข้อผิดพลาดในการอ่านไฟล์ '{filepath}': {e}")
    return None

def write_file_bytes(filepath: str, data: bytes):
  """เขียนข้อมูล bytes ลงในไฟล์"""
  try:
    with open(filepath, 'wb') as f:
      f.write(data)
    return True
  except Exception as e:
    print(f"ข้อผิดพลาดในการเขียนไฟล์ '{filepath}': {e}")
    return False

def get_required_input(prompt: str) -> str:
  while True:
    value = input(prompt).strip()
    if value:
      return value
    else:
      print("กรุณาป้อนข้อมูล")

def handle_generate_key():
  print("\n--- สร้างกุญแจ (One-Time Pad) ---")
  plaintext_file = get_required_input("ป้อนชื่อไฟล์ข้อมูลต้นฉบับ (เพื่อกำหนดความยาวกุญแจ): ")

  try:
      file_size = os.path.getsize(plaintext_file)
      if file_size == 0:
          print("ข้อผิดพลาด: ไฟล์ข้อมูลต้นฉบับว่างเปล่า")
          return
  except FileNotFoundError:
      print(f"ข้อผิดพลาด: ไม่พบไฟล์ข้อมูลต้นฉบับ '{plaintext_file}'")
      return
  except Exception as e:
      print(f"ข้อผิดพลาดในการเข้าถึงไฟล์ '{plaintext_file}': {e}")
      return

  key_file = get_required_input("ป้อนชื่อไฟล์ที่จะบันทึกกุญแจ (เช่น key.key): ")
  if os.path.exists(key_file):
      overwrite = input(f"ไฟล์ '{key_file}' มีอยู่แล้ว, ต้องการเขียนทับหรือไม่? (y/n): ").lower()
      if overwrite != 'y':
          print("ยกเลิกการสร้างกุญแจ")
          return

  try:
    print(f"กำลังสร้างกุญแจขนาด {file_size} bytes...")
    key_data = generate_key(file_size)
    if write_file_bytes(key_file, key_data):
      print(f"สร้างกุญแจสำเร็จ! บันทึกไว้ที่ '{key_file}'")
      print("!!! คำเตือน: จัดการไฟล์กุญแจนี้อย่างปลอดภัย และใช้เพียงครั้งเดียวเท่านั้น !!!")
  except ValueError as e:
      print(f"ข้อผิดพลาด: {e}")
  except Exception as e:
    print(f"เกิดข้อผิดพลาดที่ไม่คาดคิดระหว่างสร้างกุญแจ: {e}")

def handle_encrypt():
  print("\n--- เข้ารหัสไฟล์ ---")
  plaintext_file = get_required_input("ป้อนชื่อไฟล์ข้อมูลต้นฉบับที่จะเข้ารหัส: ")
  key_file = get_required_input("ป้อนชื่อไฟล์กุญแจ (.key): ")
  ciphertext_file = get_required_input("ป้อนชื่อไฟล์ที่จะบันทึกข้อมูลที่เข้ารหัส (เช่น data.enc): ")

  if os.path.exists(ciphertext_file):
      overwrite = input(f"ไฟล์ '{ciphertext_file}' มีอยู่แล้ว, ต้องการเขียนทับหรือไม่? (y/n): ").lower()
      if overwrite != 'y':
          print("ยกเลิกการเข้ารหัส")
          return

  plaintext_data = read_file_bytes(plaintext_file)
  key_data = read_file_bytes(key_file)

  if plaintext_data is None or key_data is None:
    return

  try:
    print("กำลังเข้ารหัส...")
    ciphertext_data = process_data(plaintext_data, key_data)
    if write_file_bytes(ciphertext_file, ciphertext_data):
      print(f"เข้ารหัสไฟล์สำเร็จ! บันทึกไว้ที่ '{ciphertext_file}'")
      print("!!! คำเตือน: อย่าลืมส่งไฟล์กุญแจให้ผู้รับอย่างปลอดภัย และ *ห้าม* ใช้กุญแจนี้ซ้ำอีก !!!")
  except ValueError as e:
    print(f"ข้อผิดพลาดในการเข้ารหัส: {e}")
  except Exception as e:
    print(f"เกิดข้อผิดพลาดที่ไม่คาดคิดระหว่างเข้ารหัส: {e}")

def handle_decrypt():
  print("\n--- ถอดรหัสไฟล์ ---")
  ciphertext_file = get_required_input("ป้อนชื่อไฟล์ข้อมูลที่เข้ารหัส (.enc): ")
  key_file = get_required_input("ป้อนชื่อไฟล์กุญแจ (.key) ที่ใช้คู่กัน: ")
  plaintext_file = get_required_input("ป้อนชื่อไฟล์ที่จะบันทึกข้อมูลที่ถอดรหัส (เช่น data_decrypted.txt): ")

  if os.path.exists(plaintext_file):
      overwrite = input(f"ไฟล์ '{plaintext_file}' มีอยู่แล้ว, ต้องการเขียนทับหรือไม่? (y/n): ").lower()
      if overwrite != 'y':
          print("ยกเลิกการถอดรหัส")
          return

  ciphertext_data = read_file_bytes(ciphertext_file)
  key_data = read_file_bytes(key_file)

  if ciphertext_data is None or key_data is None:
    return

  try:
    print("กำลังถอดรหัส...")
    decrypted_data = process_data(ciphertext_data, key_data)
    if write_file_bytes(plaintext_file, decrypted_data):
      print(f"ถอดรหัสไฟล์สำเร็จ! บันทึกไว้ที่ '{plaintext_file}'")
  except ValueError as e:
    print(f"ข้อผิดพลาดในการถอดรหัส: {e} (อาจเกิดจากกุญแจไม่ถูกต้อง หรือความยาวไม่พอดี)")
  except Exception as e:
    print(f"เกิดข้อผิดพลาดที่ไม่คาดคิดระหว่างถอดรหัส: {e}")

def main():
  print("=" * 40)
  print("   โปรแกรมเข้ารหัส/ถอดรหัส Vernam Cipher")
  print("=" * 40)
  print("!!! คำเตือนด้านความปลอดภัย !!!")
  print("- กุญแจต้องสร้างแบบสุ่ม, ยาวเท่าข้อมูล, และใช้เพียงครั้งเดียว")
  print("- คุณต้องรับผิดชอบในการส่งและจัดเก็บกุญแจอย่างปลอดภัย")
  print("-" * 40)

  while True:
    print("\nเลือกการทำงาน:")
    print("1: สร้างกุญแจ (Generate Key)")
    print("2: เข้ารหัสไฟล์ (Encrypt File)")
    print("3: ถอดรหัสไฟล์ (Decrypt File)")
    print("4: ออกจากโปรแกรม (Exit)")

    choice = input("เลือก (1-4): ")

    if choice == '1':
      handle_generate_key()
    elif choice == '2':
      handle_encrypt()
    elif choice == '3':
      handle_decrypt()
    elif choice == '4':
      print("กำลังออกจากโปรแกรม...")
      break
    else:
      print("ตัวเลือกไม่ถูกต้อง กรุณาเลือก 1-4")

    input("\nกด Enter เพื่อดำเนินการต่อ...")

if __name__ == "__main__":
  main()