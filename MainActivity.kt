package com.gm220s.manager

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.graphics.Color
import android.text.InputType
import android.view.Gravity
import android.widget.*
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.concurrent.Executors
import java.util.regex.Pattern

data class Device(
    val mac: String,
    val ip: String,
    val host: String,
    val port: String,
    val phyType: String
)

data class MacRule(
    val index: Int,
    val enable: String,
    val blackList: String,
    val type: String,
    val protocol: String,
    val srcMac: String,
    val dstMac: String,
    val port: String
)

class ModemClient(
    private val host: String,
    private val username: String,
    private val password: String
) {
    private var sessionToken = ""

    private fun url(path: String) = URL("http://$host$path")

    private fun request(
        method: String,
        path: String,
        body: String? = null,
        referer: String? = null
    ): Pair<Int, String> {
        val conn = (url(path).openConnection() as HttpURLConnection)
        conn.requestMethod = method
        conn.instanceFollowRedirects = false
        conn.connectTimeout = 8000
        conn.readTimeout = 8000
        conn.useCaches = false
        conn.setRequestProperty("Connection", "close")
        conn.setRequestProperty("User-Agent", "GM220-S-Manager/1.0")
        if (referer != null) conn.setRequestProperty("Referer", "http://$host$referer")
        if (body != null) {
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        }
        val code = conn.responseCode
        val stream = if (code >= 400) conn.errorStream else conn.inputStream
        val text = stream?.bufferedReader(Charsets.ISO_8859_1)?.use { it.readText() } ?: ""
        conn.disconnect()
        return code to text
    }

    private fun enc(v: String) = URLEncoder.encode(v, "UTF-8")

    private fun form(vararg pairs: Pair<String, String>) =
        pairs.joinToString("&") { "${enc(it.first)}=${enc(it.second)}" }

    private fun decodeRouter(s: String) =
        s.replace(Regex("""\\x([0-9A-Fa-f]{2})""")) {
            it.groupValues[1].toInt(16).toChar().toString()
        }

    fun login(): Result<Unit> = try {
        val (_, loginPage) = request("GET", "/")
        val token = Regex("""Frm_Logintoken[^>]*value\s*=\s*["']([^"']*)""")
            .find(loginPage)?.groupValues?.get(1)
            ?: Regex("""Frm_Logintoken.*?value\s*=\s*["'](\d+)""")
                .find(loginPage)?.groupValues?.get(1)
            ?: "5"

        val body = form(
            "frashnum" to "",
            "action" to "login",
            "Frm_Logintoken" to token,
            "username" to username,
            "Password" to password
        )
        val (code, _) = request("POST", "/", body, "/")
        if (code !in 300..399) {
            throw Exception("Login failed (HTTP $code). Check username/password.")
        }
        refreshToken()
        Result.success(Unit)
    } catch (e: Exception) {
        Result.failure(e)
    }

    private fun refreshToken() {
        val (_, body) = request("GET", "/keepAlive.gch")
        val token = body.trim()
        if (token.isNotEmpty()) sessionToken = token
    }

    private fun authenticatedGet(path: String): String {
        refreshToken()
        return request("GET", path, null, path).second
    }

    private fun authenticatedPost(path: String, body: String): String {
        refreshToken()
        return request("POST", path, body, path).second
    }

    private fun transferIndexed(html: String, key: String): Map<Int, String> {
        val result = mutableMapOf<Int, String>()
        val p = Pattern.compile(
            """Transfer_meaning\(\s*['"]${Pattern.quote(key)}(\d*)['"]\s*,\s*['"]([^'"]*)['"]\s*\)""",
            Pattern.CASE_INSENSITIVE
        )
        val m = p.matcher(html)
        while (m.find()) {
            val idx = if (m.group(1).isNullOrEmpty()) -1 else m.group(1).toInt()
            result[idx] = decodeRouter(m.group(2) ?: "")
        }
        return result
    }

    fun devices(): List<Device> {
        val html = authenticatedGet(
            "/getpage.gch?pid=1002&nextpage=net_dhcp_dynamic_t.gch"
        )
        val macs = transferIndexed(html, "MACAddr")
        val ips = transferIndexed(html, "IPAddr")
        val hosts = transferIndexed(html, "HostName")
        val ports = transferIndexed(html, "PhyPortName")
        val types = transferIndexed(html, "PhyType")

        val indices = (macs.keys + ips.keys + hosts.keys + ports.keys)
            .filter { it >= 0 }.distinct().sorted()

        return indices.mapNotNull { i ->
            val mac = macs[i].orEmpty()
            val ip = ips[i].orEmpty()
            if (mac.isBlank() && ip.isBlank()) null
            else Device(mac, ip, hosts[i].orEmpty(), ports[i].orEmpty(), types[i].orEmpty())
        }
    }

    fun macRules(): List<MacRule> {
        val html = authenticatedGet(
            "/getpage.gch?pid=1002&nextpage=sec_macfilter_conf_t.gch"
        )
        val src = transferIndexed(html, "SrcMacAddr")
        val enable = transferIndexed(html, "Enable")
        val black = transferIndexed(html, "BlackList")
        val type = transferIndexed(html, "Type")
        val protocol = transferIndexed(html, "Protocol")
        val dst = transferIndexed(html, "DstMacAddr")
        val port = transferIndexed(html, "Port")

        val count = (0..64).firstOrNull { i ->
            !src.containsKey(i) && i > (src.keys.filter { it >= 0 }.maxOrNull() ?: -1)
        } ?: 0

        val maxIndex = src.keys.filter { it >= 0 }.maxOrNull() ?: -1
        val size = maxIndex + 1

        return (0 until size).mapNotNull { i ->
            val mac = src[i].orEmpty()
            if (mac.isBlank()) null else MacRule(
                i,
                enable[i] ?: "1",
                black[i] ?: "0",
                type[i] ?: "Bridge+Route",
                protocol[i] ?: "ALL",
                mac,
                dst[i] ?: "",
                port[i] ?: ""
            )
        }
    }

    private fun commonPairs(rules: List<MacRule>): MutableList<Pair<String, String>> {
        val pairs = mutableListOf<Pair<String, String>>()
        for (r in rules) {
            pairs += "Enable${r.index}" to r.enable
            pairs += "BlackList${r.index}" to r.blackList
            pairs += "Type${r.index}" to r.type
            pairs += "Protocol${r.index}" to r.protocol
            pairs += "SrcMacAddr${r.index}" to r.srcMac
            pairs += "DstMacAddr${r.index}" to r.dstMac
            pairs += "Port${r.index}" to r.port
        }
        return pairs
    }

    fun block(mac: String): Result<Unit> = try {
        val normalized = mac.uppercase().replace('-', ':')
        val rules = macRules()
        if (rules.any { it.srcMac.equals(normalized, true) }) return Result.success(Unit)

        val pairs = mutableListOf(
            "IF_ACTION" to "new",
            "IF_ERRORSTR" to "SUCC",
            "IF_ERRORPARAM" to "SUCC",
            "IF_ERRORTYPE" to "-1",
            "IF_INDEX" to "-1",
            "IF_INSTNUM" to rules.size.toString(),
            "Enable" to "1",
            "BlackList" to "NULL",
            "Type" to "Bridge+Route",
            "Protocol" to "ALL",
            "SrcMacAddr" to normalized,
            "DstMacAddr" to "00:00:00:00:00:00",
            "Port" to ""
        )
        pairs += commonPairs(rules)
        pairs += "IsWanSrvCntl" to "NULL"
        pairs += "IpFilterTarget" to "NULL"
        pairs += "UrlFilterTarget" to "NULL"
        pairs += "UrlFilterEnable" to "NULL"
        pairs += "SrvCntlTarget" to "NULL"
        pairs += "DefaultPolicy" to "NULL"
        pairs += "MacFilterTarget" to "Discard"
        pairs += "MacFilterEnable" to "1"
        pairs += "_SESSION_TOKEN" to sessionToken

        authenticatedPost(
            "/getpage.gch?pid=1002&nextpage=sec_macfilter_conf_t.gch",
            form(*pairs.toTypedArray())
        )
        Result.success(Unit)
    } catch (e: Exception) {
        Result.failure(e)
    }

    fun unblock(mac: String): Result<Unit> = try {
        val normalized = mac.uppercase().replace('-', ':')
        val rules = macRules()
        val target = rules.firstOrNull { it.srcMac.equals(normalized, true) }
            ?: return Result.success(Unit)

        val pairs = mutableListOf(
            "IF_ACTION" to "delete",
            "IF_ERRORSTR" to "SUCC",
            "IF_ERRORPARAM" to "SUCC",
            "IF_ERRORTYPE" to "-1",
            "IF_INDEX" to target.index.toString(),
            "IF_INSTNUM" to rules.size.toString(),
            "Enable" to "",
            "BlackList" to "",
            "Type" to "",
            "Protocol" to "",
            "SrcMacAddr" to "",
            "DstMacAddr" to "",
            "Port" to ""
        )
        pairs += commonPairs(rules)
        pairs += "IsWanSrvCntl" to "0"
        pairs += "IpFilterTarget" to "0"
        pairs += "UrlFilterTarget" to "0"
        pairs += "UrlFilterEnable" to "0"
        pairs += "SrvCntlTarget" to "1"
        pairs += "DefaultPolicy" to "0"
        pairs += "MacFilterTarget" to "Discard"
        pairs += "MacFilterEnable" to "1"
        pairs += "_SESSION_TOKEN" to sessionToken

        authenticatedPost(
            "/getpage.gch?pid=1002&nextpage=sec_macfilter_conf_t.gch",
            form(*pairs.toTypedArray())
        )
        Result.success(Unit)
    } catch (e: Exception) {
        Result.failure(e)
    }
}

class MainActivity : Activity() {
    private val executor = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private lateinit var root: LinearLayout
    private lateinit var status: TextView
    private lateinit var list: LinearLayout
    private var client: ModemClient? = null

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showLogin()
    }

    private fun baseLayout() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(18), dp(18), dp(18), dp(18))
        setBackgroundColor(Color.rgb(247, 249, 247))
    }

    private fun text(value: String, size: Float = 16f) = TextView(this).apply {
        text = value
        textSize = size
        setTextColor(Color.rgb(30, 40, 30))
        setPadding(0, dp(6), 0, dp(6))
    }

    private fun button(label: String) = Button(this).apply {
        text = label
        isAllCaps = false
    }

    private fun showLogin() {
        root = baseLayout()
        val title = text("GM220-S Manager", 26f).apply { gravity = Gravity.CENTER }
        root.addView(title, LinearLayout.LayoutParams(-1, -2))

        root.addView(text("Modem IP", 14f))
        val ip = EditText(this).apply {
            setText("192.168.1.1")
            singleLine = true
        }
        root.addView(ip)

        root.addView(text("Username", 14f))
        val user = EditText(this).apply { singleLine = true }
        root.addView(user)

        root.addView(text("Password", 14f))
        val pass = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            singleLine = true
        }
        root.addView(pass)

        status = text("Connect the phone to the GM220-S Wi-Fi first.", 14f)
        root.addView(status)

        val login = button("LOGIN")
        root.addView(login, LinearLayout.LayoutParams(-1, -2))

        login.setOnClickListener {
            login.isEnabled = false
            status.text = "Connecting..."
            val c = ModemClient(ip.text.toString().trim(), user.text.toString(), pass.text.toString())
            executor.execute {
                val result = c.login()
                main.post {
                    if (result.isSuccess) {
                        client = c
                        showDashboard()
                    } else {
                        login.isEnabled = true
                        status.text = result.exceptionOrNull()?.message ?: "Login failed"
                    }
                }
            }
        }
        setContentView(root)
    }

    private fun showDashboard() {
        root = baseLayout()
        root.addView(text("GM220-S Manager", 24f))
        status = text("Loading...", 14f)
        root.addView(status)

        val refresh = button("↻ Refresh devices")
        root.addView(refresh)

        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val scroll = ScrollView(this).apply { addView(list) }
        root.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))

        val logout = button("Logout")
        root.addView(logout)
        logout.setOnClickListener {
            client = null
            showLogin()
        }

        refresh.setOnClickListener { loadDevices() }
        setContentView(root)
        loadDevices()
    }

    private fun loadDevices() {
        status.text = "Loading connected devices..."
        list.removeAllViews()

        executor.execute {
            try {
                val c = client ?: throw Exception("Not logged in")
                val devices = c.devices()
                val rules = c.macRules()
                val blocked = rules.map { it.srcMac.uppercase() }.toSet()

                main.post {
                    status.text = "Connected/DHCP devices: ${devices.size}"
                    if (devices.isEmpty()) {
                        list.addView(text("No DHCP clients found."))
                        return@post
                    }

                    devices.forEach { d ->
                        val card = LinearLayout(this).apply {
                            orientation = LinearLayout.VERTICAL
                            setPadding(dp(12), dp(10), dp(12), dp(10))
                            setBackgroundColor(Color.WHITE)
                        }
                        card.addView(text(d.host.ifBlank { "Unknown device" }, 18f))
                        card.addView(text("IP: ${d.ip}", 14f))
                        card.addView(text("MAC: ${d.mac}", 14f))
                        card.addView(text("Port: ${d.port.ifBlank { d.phyType }}", 14f))

                        val action = button(
                            if (blocked.contains(d.mac.uppercase())) "UNBLOCK" else "BLOCK"
                        )
                        card.addView(action)

                        action.setOnClickListener {
                            action.isEnabled = false
                            status.text = "Updating MAC filter..."
                            executor.execute {
                                val result = if (blocked.contains(d.mac.uppercase())) {
                                    c.unblock(d.mac)
                                } else {
                                    c.block(d.mac)
                                }
                                main.post {
                                    action.isEnabled = true
                                    if (result.isSuccess) {
                                        loadDevices()
                                    } else {
                                        status.text = result.exceptionOrNull()?.message ?: "Operation failed"
                                    }
                                }
                            }
                        }

                        val lp = LinearLayout.LayoutParams(-1, -2)
                        lp.setMargins(0, dp(8), 0, dp(8))
                        list.addView(card, lp)
                    }
                }
            } catch (e: Exception) {
                main.post { status.text = "Error: ${e.message}" }
            }
        }
    }

    override fun onDestroy() {
        executor.shutdownNow()
        super.onDestroy()
    }
}
