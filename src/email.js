export async function sendCodeEmail(to, code, env) {
	const AccessKeyId = env.ALIYUN_ACCESS_KEY_ID;
	const AccessKeySecret = env.ALIYUN_ACCESS_KEY_SECRET;

	// 创建更美观的HTML邮件模板
	const htmlBody = `
<body style="margin: 0; padding: 0; font-family: sans-serif;">
	<table border="0" cellpadding="0" cellspacing="0" width="100%">
		<tr>
			<td align="center">
				<table border="0" cellpadding="0" cellspacing="0" width="600">
					<tr>
						<td style="padding: 20px 0; text-align: center;">
							<h1 style="color: #333;">StarryCognition</h1>
						</td>
					</tr>
					<tr>
						<td style="padding: 20px; background-color: #f8f9fa; border-radius: 5px;">
							<h3>您的登录验证码</h3>
							<p>您好！您正在尝试登录 StarryCognition 账户。</p>
							<div style="text-align: center; padding: 20px;">
								<span style="display: inline-block; font-size: 32px; font-weight: bold; color: #0070f3; letter-spacing: 5px; padding: 15px 25px; border: 2px dashed #0070f3; border-radius: 5px;">${code}</span>
							</div>
							<p style="color: #666; font-size: 14px;">验证码有效期为5分钟，请勿泄露。如果这不是您本人操作，请忽略此邮件。</p>
						</td>
					</tr>
					<tr>
						<td style="padding: 20px 0; text-align: center; color: #999; font-size: 12px;">
							<p>&copy; 2025 StarryCognition. All rights reserved.</p>
						</td>
					</tr>
				</table>
			</td>
		</tr>
	</table>
</body>`;

	const params = {
		Action: 'SingleSendMail',    
		AccountName: 'noreply@mail.starrycognition.cn',
		ReplyToAddress: 'false',
		AddressType: '1',
		ToAddress: to,
		FromAlias: 'StarryCognition',
		Subject: '登录验证码',
		HtmlBody: htmlBody,
		Format: 'json',
		Version: '2015-11-23',
		AccessKeyId,
		SignatureMethod: 'HMAC-SHA1',
		Timestamp: new Date().toISOString(),
		SignatureVersion: '1.0',
		SignatureNonce: crypto.randomUUID(),
		RegionId: 'cn-hangzhou',
	};

	// ① 按字典序排序
	const sorted = Object.keys(params)
		.sort()
		.map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`)
		.join('&');
	// ② 构造待签名字符串
	const stringToSign = `GET&%2F&${encodeURIComponent(sorted)}`;
	// ③ 计算 HMAC-SHA1 + Base64
	const key = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(AccessKeySecret + '&'),
		{ name: 'HMAC', hash: 'SHA-1' },
		false,
		['sign']
	);
	const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(stringToSign));
	
	// 修复Workers环境下btoa不支持中文的问题
	const sigArray = new Uint8Array(sig);
	const chunkSize = 0x8000;
	let str = '';
	for (let i = 0; i < sigArray.length; i += chunkSize) {
		str += String.fromCharCode.apply(null, sigArray.subarray(i, i + chunkSize));
	}
	params.Signature = btoa(str);

	const res = await fetch('https://dm.aliyuncs.com?' + new URLSearchParams(params));
	if (!res.ok) throw new Error('AliDM error ' + res.status);
}