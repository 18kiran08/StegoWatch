// 测试文件：中文注释和字符串
// Test file: Chinese comments and strings
// Purpose: Verify that legitimate Chinese code doesn't trigger false positives

/**
 * 用户认证模块
 * User Authentication Module
 * 
 * 这个模块负责处理用户登录、注册和权限验证
 * This module handles user login, registration, and permission verification
 */

// ===== TEST 1: Chinese Comments (Should NOT be flagged) =====
// 这是一个普通的中文注释
// 功能：获取用户信息
function getUserInfo(userId) {
    // 验证用户ID是否有效
    if (!userId) {
        throw new Error('用户ID不能为空');
    }
    
    return {
        id: userId,
        name: '张三',
        email: 'zhangsan@example.com',
        // 用户角色：管理员
        role: 'admin'
    };
}

// ===== TEST 2: Chinese String Literals (Should NOT be flagged) =====
const messages = {
    welcome: '欢迎使用我们的应用程序',
    loginSuccess: '登录成功！',
    loginFailed: '登录失败，请检查用户名和密码',
    goodbye: '再见！感谢使用',
    error: '发生错误，请稍后重试'
};

// ===== TEST 3: Template Literals with Chinese (Should NOT be flagged) =====
function greetUser(username) {
    const greeting = `你好，${username}！欢迎回来。`;
    console.log(greeting);
    return greeting;
}

// ===== TEST 4: Multi-line Chinese Comments (Should NOT be flagged) =====
/*
 * 数据处理函数
 * 
 * 参数说明：
 * - data: 输入数据数组
 * - filter: 过滤条件
 * 
 * 返回值：
 * - 处理后的数据数组
 */
function processData(data, filter) {
    // 应用过滤条件
    return data.filter(item => {
        // 检查是否满足条件
        return filter(item);
    });
}

// ===== TEST 5: Chinese in Object Properties (Should NOT be flagged) =====
const config = {
    应用名称: '我的应用',
    版本: '1.0.0',
    描述: '这是一个测试应用程序',
    作者: {
        姓名: '开发者',
        邮箱: 'dev@example.com'
    }
};

// ===== TEST 6: Chinese Error Messages (Should NOT be flagged) =====
class CustomError extends Error {
    constructor(message) {
        super(message);
        this.name = '自定义错误';
    }
}

function validateInput(input) {
    if (!input) {
        throw new CustomError('输入不能为空');
    }
    if (input.length < 3) {
        throw new CustomError('输入长度必须大于3个字符');
    }
}

// ===== TEST 7: Inline Chinese Comments (Should NOT be flagged) =====
const user = {
    name: 'User',      // 用户名称
    age: 25,           // 用户年龄
    city: 'Beijing',   // 所在城市
    active: true       // 账户状态：激活
};

// ===== TEST 8: Chinese in Console Logs (Should NOT be flagged) =====
function debugLog(operation, data) {
    console.log('操作:', operation);
    console.log('数据:', data);
    console.log('时间:', new Date().toLocaleString('zh-CN'));
}

// ===== TEST 9: Chinese Regex Patterns (Should NOT be flagged) =====
// 验证中文字符的正则表达式
const chinesePattern = /[\u4e00-\u9fa5]+/;
const mixedPattern = /^[\u4e00-\u9fa5a-zA-Z0-9]+$/;

function containsChinese(text) {
    // 检查文本是否包含中文字符
    return chinesePattern.test(text);
}

// ===== TEST 10: Documentation with Chinese (Should NOT be flagged) =====
/**
 * 计算两个数字的和
 * Calculate the sum of two numbers
 * 
 * @param {number} a - 第一个数字
 * @param {number} b - 第二个数字
 * @returns {number} 两个数字的和
 * 
 * @example
 * const result = add(5, 3); // 返回 8
 */
function add(a, b) {
    return a + b;
}

// ===== TEST 11: Mixed Language Code (Should NOT be flagged) =====
const apiEndpoints = {
    // 用户相关接口 / User related endpoints
    getUser: '/api/user',
    // 订单相关接口 / Order related endpoints  
    createOrder: '/api/order/create',
    // 支付相关接口 / Payment related endpoints
    processPayment: '/api/payment/process'
};

// ===== TEST 12: Chinese with Special Characters (Should NOT be flagged) =====
const specialMessages = {
    question: '你确定要继续吗？',
    exclamation: '警告！数据将被删除！',
    quotation: '他说："这很重要"',
    parentheses: '请输入有效的值（1-100）'
};

// Export for testing
module.exports = {
    getUserInfo,
    greetUser,
    processData,
    config,
    validateInput,
    debugLog,
    containsChinese,
    add,
    apiEndpoints,
    messages,
    specialMessages
};

console.log('中文测试文件加载完成 / Chinese test file loaded successfully');

