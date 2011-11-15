require 'rubygems'
require 'base32'
require 'gibberish'
require 'securerandom'
require 'yaml'

class Vault
  # The encrypted YAML file
  FILE = 'vault.yml'

  # The key size used to encrypt the vault file
  KEY_SIZE = 256

  # The TOTP time slice in seconds
  INTERVAL = 30

  def initialize(password)
    @cipher  = Gibberish::AES.new password, KEY_SIZE
    @secrets = {} # the user secrets
    @recent  = {} # used to prevent replay attacks

    if File.exists? FILE
      begin
        @secrets = YAML.load @cipher.decrypt File.read FILE
      rescue
        puts "Invalid vault password, terminating."
        exit 1
      end
    end
  end

  # Returns true if the given attempt is a valid TOTP for the given uid
  def authenticate(uid, attempt)
    # Fail early if the user is not in the secret map
    validate uid

    # Fail early if this attempt is found in the replay log
    return false if is_repeat? uid, attempt

    now = Time.now.to_i / INTERVAL
    key = Base32.decode @secrets[uid]
    sha = OpenSSL::Digest::Digest.new 'sha1'

    # Check the previous, current, and next intervals
    (-1..1).each do |x|
      bytes  = [ now + x ].pack('>q').reverse
      hmac   = OpenSSL::HMAC.digest sha, key, bytes
      offset = hmac[-1] & 0x0F
      hash   = hmac[offset...offset + 4]

      code = hash.reverse.unpack('L')[0]
      code &= 0x7FFFFFFF
      code %= 1000000

      if code == attempt.to_i
        remember_attempt uid, code
        return true
      end
    end

    return false
  end

  # Removes the given uid from the secrets map
  def delete(uid)
    validate uid
    @secrets.delete uid
    sync
    return true
  end

  # Add a uid to the secret map and return the new secret
  def insert(uid)
    raise ArgumentError, "Existing secret for #{uid}!" if @secrets.include? uid
    @secrets[uid] = random_key
    sync
    return @secrets[uid]
  end

  # Returns a list of all the uids in the secret map
  def members
    @secrets.keys
  end

  private

  # Add a code to the replay log for the given uid
  def remember_attempt(uid, code)
    @recent[uid] ||= []
    @recent[uid] << [ Time.now.to_i, code.to_i ]
  end

  # Checks to see if the given code is in the replay log for the given uid
  def is_repeat?(uid, code)
    forget_old_attempts uid
    @recent[uid].collect {|e| e.last }.include?(code.to_i)
  end

  # Clear old attempts from the replay log
  def forget_old_attempts(uid)
    now = Time.now.to_i
    @recent[uid] ||= []
    @recent[uid].delete_if {|e| now - e.first > INTERVAL * 2 }
  end

  # Generates a random key for use as a shared secret
  def random_key
    Base32.encode SecureRandom.random_bytes 10
  end

  # Encrypts and writes the contents of the secret map to disk
  def sync
    File.open(FILE, 'w') {|f| f.puts @cipher.encrypt YAML.dump @secrets }
  end

  # Raises an error if the given uid is not present in the secret map
  def validate(uid)
    raise ArgumentError, "No secret for #{uid}!" unless @secrets.include? uid
  end
end
