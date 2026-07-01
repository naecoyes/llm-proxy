import re

with open("server.py", "r") as f:
    content = f.read()

# 1. Add _get_mimo_free_token
mimo_token_func = """
    async def _get_mimo_free_token(self) -> str:
        \"\"\"动态获取 Mimo Free API 的 JWT Token\"\"\"
        if not hasattr(self, "_mimo_free_token") or not hasattr(self, "_mimo_free_token_expiry"):
            self._mimo_free_token = None
            self._mimo_free_token_expiry = 0

        import time
        if self._mimo_free_token and time.time() < self._mimo_free_token_expiry:
            return self._mimo_free_token

        url = "https://api.xiaomimimo.com/api/free-ai/bootstrap"
        try:
            response = await self.http_client.post(url, json={"client": "llm-proxy-auto"})
            if response.status_code == 200:
                data = response.json()
                self._mimo_free_token = data.get("jwt")
                # Token valid for ~1 hour, refresh after 50 minutes (3000 seconds)
                self._mimo_free_token_expiry = time.time() + 3000
                logger.info("成功获取 Mimo Free JWT Token")
                return self._mimo_free_token
            else:
                logger.error(f"获取 Mimo Free Token 失败: HTTP {response.status_code}")
                return ""
        except Exception as e:
            logger.error(f"获取 Mimo Free Token 异常: {e}")
            return ""

    async def forward_request(
"""
content = content.replace("    async def forward_request(", mimo_token_func)


# 2. Modify _forward_openai
old_openai = """        url = f"{model_config.api_base}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {model_config.api_key}",
        }"""
new_openai = """        url = model_config.api_base if model_config.is_exact_url else f"{model_config.api_base}/chat/completions"
        
        api_key = model_config.api_key
        headers = {
            "Content-Type": "application/json",
        }
        
        if getattr(model_config, "provider", "") == "mimo-free":
            api_key = await self._get_mimo_free_token()
            headers["X-Mimo-Source"] = "mimocode-cli-free"
            
        headers["Authorization"] = f"Bearer {api_key}"
        
        # Add custom headers
        if hasattr(model_config, "custom_headers") and model_config.custom_headers:
            headers.update(model_config.custom_headers)
"""
content = content.replace(old_openai, new_openai)

# 3. Modify test_model for OpenAI format
old_test_openai = """                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {model_config.api_key}",
                }

                url = f"{model_config.api_base}/chat/completions"

                response = await self.http_client.post(
                    url, json=test_body, headers=headers, timeout=30
                )"""

new_test_openai = """                url = model_config.api_base if model_config.is_exact_url else f"{model_config.api_base}/chat/completions"
                
                api_key = model_config.api_key
                headers = {
                    "Content-Type": "application/json",
                }
                
                if getattr(model_config, "provider", "") == "mimo-free":
                    api_key = await self._get_mimo_free_token()
                    headers["X-Mimo-Source"] = "mimocode-cli-free"
                    
                headers["Authorization"] = f"Bearer {api_key}"
                
                if hasattr(model_config, "custom_headers") and model_config.custom_headers:
                    headers.update(model_config.custom_headers)

                response = await self.http_client.post(
                    url, json=test_body, headers=headers, timeout=30
                )"""
content = content.replace(old_test_openai, new_test_openai)

with open("server.py", "w") as f:
    f.write(content)
