# name: discourse-migratepassword
# about: enable alternative password hashes
# version: 0.9.1
# authors: Jens Maier and michael@communiteq.com and Michiel Hendriks
# url: https://github.com/elmuerte/discourse-migratepassword

# Usage:
# When migrating, store a custom field with the user containing the crypted password

#This will be applied at runtime, as authentication is attempted.  It does not apply at migration time.

gem "bcrypt", "3.1.18"

enabled_site_setting :migratepassword_enabled

require "digest"

after_initialize do
  module ::AlternativePassword
    def confirm_password?(password)
      return true if super
      return false unless SiteSetting.migratepassword_enabled
      return false unless self.custom_fields.has_key?("import_pass")

      if AlternativePassword.check_all(
           password,
           self.custom_fields["import_pass"]
         )
        self.password = password
        self.custom_fields.delete("import_pass")

        if SiteSetting.migratepassword_allow_insecure_passwords
          return save(validate: false)
        else
          return save
        end
      end
      false
    end

    def self.check_all(password, crypted_pass)
      AlternativePassword.check_mbn(password, crypted_pass)
    end

    def self.check_mbn(password, crypted_pass)
      hash, salt = crypted_pass.split(":", 2)
      hash.gsub! /^\$2y\$/, "$2a$"
      pass = Digest::MD5.hexdigest(password) + salt
      if hash.start_with?("$v")
        hash.gsub! /^\$v.\$/, "$2a$"
        pass = Digest::MD5.hexdigest(Digest::MD5.hexdigest(password) + salt)
      end
      begin
        BCrypt::Password.new(hash) == pass
      rescue StandardError
        false
      end
    end
  end

  class ::User
    prepend AlternativePassword
  end
end
