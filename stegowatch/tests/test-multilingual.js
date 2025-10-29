// 多语言测试文件 / Multilingual Test File
// Tests that legitimate non-English text doesn't trigger false positives

// ===== CHINESE (中文) =====
// 这是一个中文注释
const greeting_cn = '你好世界';
const user_cn = {
    姓名: '王小明',
    描述: '软件工程师'
};

// ===== JAPANESE (日本語) =====
// これは日本語のコメントです
const greeting_jp = 'こんにちは世界';
const user_jp = {
    名前: '田中太郎',
    説明: 'ソフトウェアエンジニア'
};

// ===== KOREAN (한국어) =====
// 이것은 한국어 주석입니다
const greeting_kr = '안녕하세요 세계';
const user_kr = {
    이름: '김철수',
    설명: '소프트웨어 엔지니어'
};

// ===== ARABIC (العربية) =====
// هذا تعليق باللغة العربية
const greeting_ar = 'مرحبا بالعالم';
const user_ar = {
    الاسم: 'محمد',
    الوصف: 'مهندس برمجيات'
};

// ===== RUSSIAN (Русский) =====
// Это комментарий на русском языке
const greeting_ru = 'Привет мир';
const user_ru = {
    имя: 'Иван Петров',
    описание: 'Инженер-программист'
};

// ===== HINDI (हिन्दी) =====
// यह हिंदी में एक टिप्पणी है
const greeting_hi = 'नमस्ते दुनिया';
const user_hi = {
    नाम: 'राज कुमार',
    विवरण: 'सॉफ्टवेयर इंजीनियर'
};

// ===== HEBREW (עברית) =====
// זהו הערה בעברית
const greeting_he = 'שלום עולם';
const user_he = {
    שם: 'דוד כהן',
    תיאור: 'מהנדס תוכנה'
};

// ===== THAI (ไทย) =====
// นี่คือความคิดเห็นภาษาไทย
const greeting_th = 'สวัสดีชาวโลก';
const user_th = {
    ชื่อ: 'สมชาย',
    คำอธิบาย: 'วิศวกรซอฟต์แวร์'
};

// ===== VIETNAMESE (Tiếng Việt) =====
// Đây là một bình luận tiếng Việt
const greeting_vi = 'Xin chào thế giới';
const user_vi = {
    tên: 'Nguyễn Văn An',
    mô_tả: 'Kỹ sư phần mềm'
};

// ===== GREEK (Ελληνικά) =====
// Αυτό είναι ένα σχόλιο στα ελληνικά
const greeting_el = 'Γεια σου κόσμε';
const user_el = {
    όνομα: 'Γιάννης Παπαδόπουλος',
    περιγραφή: 'Μηχανικός λογισμικού'
};

// ===== MIXED LANGUAGES IN DOCUMENTATION =====
/**
 * 多语言支持函数
 * マルチ言語サポート関数
 * 다국어 지원 기능
 * Multilingual support function
 * 
 * @param {string} lang - Language code (zh/ja/ko/ar/ru/hi/he/th/vi/el)
 * @returns {Object} Localized user data
 */
function getLocalizedData(lang) {
    const translations = {
        zh: { welcome: '欢迎', goodbye: '再见' },
        ja: { welcome: 'ようこそ', goodbye: 'さようなら' },
        ko: { welcome: '환영합니다', goodbye: '안녕히 가세요' },
        ar: { welcome: 'مرحبا', goodbye: 'وداعا' },
        ru: { welcome: 'Добро пожаловать', goodbye: 'До свидания' },
        hi: { welcome: 'स्वागत', goodbye: 'अलविदा' },
        he: { welcome: 'ברוך הבא', goodbye: 'להתראות' },
        th: { welcome: 'ยินดีต้อนรับ', goodbye: 'ลาก่อน' },
        vi: { welcome: 'Chào mừng', goodbye: 'Tạm biệt' },
        el: { welcome: 'Καλώς ήρθατε', goodbye: 'Αντίο' }
    };
    
    return translations[lang] || translations['en'];
}

// ===== EMOJI AND SPECIAL CHARACTERS (Legitimate use) =====
const statusMessages = {
    success: '✓ 操作成功',
    error: '✗ エラーが発生しました',
    warning: '⚠ 경고: 주의하세요',
    info: 'ℹ معلومات مهمة'
};

// ===== ALL THESE SHOULD NOT TRIGGER FALSE POSITIVES =====
// None of the above code should be flagged as suspicious
// They are all legitimate uses of non-English text

console.log('多语言测试文件加载完成');
console.log('マルチ言語テストファイルが読み込まれました');
console.log('다국어 테스트 파일이 로드되었습니다');

module.exports = {
    getLocalizedData,
    statusMessages,
    // Export all greetings
    greetings: {
        chinese: greeting_cn,
        japanese: greeting_jp,
        korean: greeting_kr,
        arabic: greeting_ar,
        russian: greeting_ru,
        hindi: greeting_hi,
        hebrew: greeting_he,
        thai: greeting_th,
        vietnamese: greeting_vi,
        greek: greeting_el
    }
};

