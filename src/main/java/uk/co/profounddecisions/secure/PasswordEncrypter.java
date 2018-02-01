package uk.co.profounddecisions.secure;

import org.mindrot.jbcrypt.BCrypt;

public class PasswordEncrypter {

    private final String pepper;

    public PasswordEncrypter(String pepper) {
        this.pepper = pepper;
    }

    public String encrypted(String password, String salt) {
        // we add the pepper to the password before hashing because BCrypt has a very specific idea of what
        // a salt looks like
        return BCrypt.hashpw(password + pepper, salt);
    }

    public boolean isValid(String plaintextCandidate, String fromDB) {
        return BCrypt.checkpw(plaintextCandidate + pepper, fromDB);
    }

}
