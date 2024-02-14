/** User class for message.ly */
const db = require("../db");
const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR } = require("../config");
const ExpressError = require("../expressError");


/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    try
    {
      const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);

      const result = await db.query(
        `
        INSERT INTO users 
          (username, password, first_name, last_name, phone)
        VALUES 
          ($1, $2, $3, $4, $5)
        RETURNING 
          username, first_name, last_name, phone
        `,
        [username, hashedPassword, first_name, last_name, phone]
      );

      return result.rows[0];


    }
    catch(error)
    {
      if (error.code === "23505" && error.constraint === "users_username_key") {
        throw new ExpressError(`Username '${username}' is already taken.`, 400);
      }
    }
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) { 
    const result = await db.query(`
    SELECT username, password FROM users WHERE username = $1`, [username])

    if (result.rows.length === 0) {
      return false;
    }

    const user = result.rows[0];
    const hashedPassword = user.password;

    // Use bcrypt to compare the provided password with the hashed password
    const isValidPassword = await bcrypt.compare(password, hashedPassword);

    // Return the result of the password comparison
    return isValidPassword;
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 
    const result = await db.query(`
    UPDATE users SET last_login_at = current_timestamp WHERE username  = $1 RETURNING username, last_login_at`,
    [username]);

    if (!result.rows[0]) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }

    return result.rows[0];
  }
  

  

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const result = await db.query(`
    SELECT username, first_name, last_name, phone FROM users`);

    return result.rows[0];

   }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    const result = await db.query(`
    SELECT first_name, last_name, phone, join_at, last_login_at FROM users WHERE username = $1`, 
    [username]);

    if (!result.rows[0]) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }

    return result.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    const result = await db.query(`
    SELECT m.id, 
              m.to_username AS to_user, 
              m.body, 
              m.sent_at, 
              m.read_at,
              u.first_name, 
              u.last_name, 
              u.phone
       FROM messages AS m
       JOIN users AS u ON m.to_username = u.username
       WHERE m.from_username = $1`,
       [username]);

       return result.rows;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    const result = await db.query(
      `SELECT m.id, 
              m.from_username AS from_user, 
              m.body, 
              m.sent_at, 
              m.read_at,
              u.first_name, 
              u.last_name, 
              u.phone
       FROM messages AS m
       JOIN users AS u ON m.from_username = u.username
       WHERE m.to_username = $1`,
      [username]
    );

    // Return the array of message information
    return result.rows;
  }
}


module.exports = User;