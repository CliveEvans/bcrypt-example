package uk.co.profounddecisions.secure;

import org.junit.Test;
import org.mindrot.jbcrypt.BCrypt;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

public class PasswordEncrypterTest {

    @Test
    public void shouldReturnADifferentValue() throws Exception {
        String salt = BCrypt.gensalt();
        String pepper = "mix it up";

        PasswordEncrypter passwordEncrypter = new PasswordEncrypter(pepper);

        String password = "password";
        String encrypted = passwordEncrypter.encrypted(password, salt);
        assertThat(encrypted, not(isEmptyString()));
        assertThat(encrypted, not(equalTo(password)));
    }

    @Test
    public void shouldCorrectlyVerifyPassword() throws Exception {
        String salt = BCrypt.gensalt();
        String pepper = "mix it up";

        PasswordEncrypter passwordEncrypter = new PasswordEncrypter(pepper);

        String password = "password";
        String encrypted = passwordEncrypter.encrypted(password, salt);

        assertTrue(passwordEncrypter.isValid(password, encrypted));
    }

    @Test
    public void theHashedPasswordStartsWithTheSalt() {
        // this is how it can verify a password without looking up the salt - you only need one password column in this version
        String salt = BCrypt.gensalt();
        String password = "password";

        String firstEncrypted = new PasswordEncrypter("mix it up").encrypted(password, salt);

        assertThat(firstEncrypted, startsWith(salt));
    }

    @Test
    public void shouldUseThePepper() {
        String salt = BCrypt.gensalt();
        String password = "password";

        String firstEncrypted = new PasswordEncrypter("mix it up").encrypted(password, salt);
        String secondEncrypted = new PasswordEncrypter("all the way up").encrypted(password, salt);

        assertThat(firstEncrypted, not(equalTo(secondEncrypted)));
    }
}