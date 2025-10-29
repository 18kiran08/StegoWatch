// 测试文件：包含真实可疑模式的中文代码
// Test file: Chinese code WITH actual suspicious patterns
// Purpose: Verify detector can distinguish legitimate Chinese from actual threats

// ===== LEGITIMATE: Chinese Comments (Should NOT be flagged) =====
// 这是一个正常的函数
function normalFunction() {
    // 打印消息
    console.log('正常的日志消息');
}

// ===== SUSPICIOUS: eval with base64 (SHOULD be flagged) =====
// 这个代码包含可疑的 eval 调用
function suspiciousCode() {
    // 注意：这是可疑的代码模式
    eval(atob('Y29uc29sZS5sb2coInN1c3BpY2lvdXMiKQ=='));
}

// ===== LEGITIMATE: Chinese String (Should NOT be flagged) =====
const message = '欢迎使用我们的应用';

// ===== SUSPICIOUS: Excessive indentation (SHOULD be flagged) =====
function hiddenCode() {
                                                                                                                                                                                                                                                                                                    console.log('这行代码被过度缩进隐藏了');
}

// ===== LEGITIMATE: Chinese Object (Should NOT be flagged) =====
const user = {
    名字: '张三',
    年龄: 30,
    城市: '北京'
};

// ===== SUSPICIOUS: Dynamic eval pattern (SHOULD be flagged) =====
// 动态代码执行
const dynamicCode = (code) => {
    // 这个模式是可疑的
    return new Function(code)();
};

// ===== LEGITIMATE: Chinese Comment (Should NOT be flagged) =====
/*
 * 多行中文注释
 * 这里描述了一些功能
 * 应该不会被标记为问题
 */

// ===== SUSPICIOUS: This line contains invisible Unicode characters (SHOULD be flagged) =====
// The next line has zero-width spaces embedded (invisible):
const usernam​e = 'test'; // There's a zero-width space in 'username'

// ===== LEGITIMATE: More Chinese text (Should NOT be flagged) =====
function processOrder(orderId) {
    // 处理订单逻辑
    const order = {
        订单号: orderId,
        状态: '处理中',
        备注: '这是一个普通的订单'
    };
    
    return order;
}

// ===== Summary =====
// Expected detections: 4 suspicious patterns
// Expected non-detections: All Chinese comments and strings should be fine

console.log('测试文件已加载');

