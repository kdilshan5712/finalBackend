const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/**
 * Send an OTP email with multilingual support
 * @param {string} to - Recipient email
 * @param {string} subject - Email subject
 * @param {string} otp - The OTP code
 */
const sendEmail = async (to, subject, otp) => {
  const mailOptions = {
    from: `"Film Hall Auth System" <${process.env.EMAIL_USER}>`,
    to,
    subject,
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
        <h2>${subject}</h2>
        <p><strong>Your OTP is:</strong> <span style="font-size: 24px; color: #1a73e8;">${otp}</span></p>
        <hr/>
        <p><strong>English:</strong> If you did not request this, please ignore this email.</p>
        <p><strong>සිංහල:</strong> ඔබ මෙය ඉල්ලූවක් නොවන්නේ නම්, කරුණාකර මෙම විද්‍යුත් තැපෑල නොසලකා හරින්න.</p>
        <p><strong>தமிழ்:</strong> நீங்கள் இதை கோரவில்லை என்றால், தயவுசெய்து இந்த மின்னஞ்சலை புறக்கணிக்கவும்.</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;
