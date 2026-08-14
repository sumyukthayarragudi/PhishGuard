import { useState } from "react";
import {
  Shield,
  Activity,
  AlertTriangle,
  Link,
  Mail,
  Zap,
  Search,
  ShieldAlert,
  ShieldCheck,
  BarChart3,
  Globe,
  Lock,
  ExternalLink,
} from "lucide-react";
import { motion } from "framer-motion";

type InputType = "url" | "email";

interface RiskFeature {
  name: string;
  score: number;
  impact: string;
  explanation: string;
}

interface AnalysisResult {
  url?: string;
  email?: string;
  prediction: string;
  confidence: number;
  agreement?: string;
  models?: {
    random_forest: {
      prediction: string;
      confidence: number;
    };
    svm: {
      prediction: string;
      confidence: number;
    };
  };
  reasons?: string[];
  features?: Record<string, number | boolean>;
  risk?: {
    riskScore: number;
    rawProbability: number;
    calibratedProbability: number;
    riskLevel: string;
    riskLabel: string;
    detectedFeatures: RiskFeature[];
    summary: string;
  };
}

function App() {
  const [input, setInput] = useState("");
  const [inputType, setInputType] = useState<InputType>("url");

  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [totalScans, setTotalScans] = useState(0);
  const [highRiskCount, setHighRiskCount] = useState(0);
  const [suspiciousCount, setSuspiciousCount] = useState(0);
  const [riskScores, setRiskScores] = useState<number[]>([]);

  const averageRisk =
    riskScores.length > 0
      ? Math.round(
          riskScores.reduce((sum, score) => sum + score, 0) /
            riskScores.length
        )
      : 0;

  const analyzeInput = async () => {
    if (!input.trim()) {
      setError(
        inputType === "url"
          ? "Please enter a URL to analyze."
          : "Please paste email content to analyze."
      );
      return;
    }

    setLoading(true);
    setError("");

    try {
      const endpoint =
        inputType === "url"
          ? "http://127.0.0.1:8001/predict"
          : "http://127.0.0.1:8001/predict-email";

      const body =
        inputType === "url"
          ? { url: input }
          : { email: input };

      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        throw new Error(`Backend returned ${response.status}`);
      }

      const data: AnalysisResult = await response.json();

      setResult(data);

      setTotalScans((previous) => previous + 1);

      const isPhishing =
        String(data.prediction).toLowerCase().includes("phishing");

      if (isPhishing) {
        setHighRiskCount((previous) => previous + 1);
      } else {
        setSuspiciousCount((previous) => previous + 1);
      }

      if (data.risk?.riskScore !== undefined) {
        setRiskScores((previous) => [
          ...previous,
          data.risk!.riskScore,
        ]);
      } else {
        setRiskScores((previous) => [
          ...previous,
          data.confidence,
        ]);
      }
    } catch (err) {
      console.error(err);

      setError(
        "Could not connect to PhishGuard backend. Make sure Uvicorn is running on port 8001."
      );
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const useSample = (sample: string) => {
    setInput(sample);
    setError("");
    setResult(null);
  };

  const riskIsHigh =
    result?.risk?.riskLevel?.toLowerCase() === "high" ||
    String(result?.prediction).toLowerCase().includes("phishing");

  return (
    <div className="min-h-screen bg-[#020817] text-slate-100">

      {/* ================= NAVBAR ================= */}

      <nav className="border-b border-slate-800/80 bg-[#030b18]">
        <div className="mx-auto flex max-w-[1250px] items-center justify-between px-6 py-4">

          <div className="flex items-center gap-3">

            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-400/40 bg-cyan-400/5">
              <Shield className="h-6 w-6 text-cyan-400" />
            </div>

            <div>
              <h1 className="text-lg font-bold tracking-wide">
                PHISH<span className="text-cyan-400">GUARD</span>
              </h1>

              <p className="text-[9px] font-medium tracking-[0.2em] text-slate-500">
                EXPLAINABLE PHISHING DETECTION
              </p>
            </div>

          </div>

          <div className="flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/5 px-4 py-2 text-xs text-emerald-400">
            <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399]" />
            System Active
          </div>

        </div>
      </nav>


      {/* ================= MAIN ================= */}

      <main className="mx-auto max-w-[1250px] px-6 py-6">


        {/* ================= STAT CARDS ================= */}

        <section className="mb-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">

          <StatCard
            title="TOTAL SCANS"
            value={totalScans}
            icon={<Activity className="h-5 w-5" />}
            border="cyan"
          />

          <StatCard
            title="HIGH RISK"
            value={highRiskCount}
            icon={<ShieldAlert className="h-5 w-5" />}
            border="red"
          />

          <StatCard
            title="SUSPICIOUS"
            value={suspiciousCount}
            icon={<AlertTriangle className="h-5 w-5" />}
            border="yellow"
          />

          <StatCard
            title="AVG RISK SCORE"
            value={`${averageRisk}%`}
            icon={<ShieldCheck className="h-5 w-5" />}
            border="green"
          />

        </section>


        {/* ================= MAIN WORKSPACE ================= */}

        <section className="grid gap-5 lg:grid-cols-[1fr_1.05fr]">


          {/* ================= THREAT SCANNER ================= */}

          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="rounded-xl border border-slate-800 bg-[#071123] p-5 shadow-[0_0_30px_rgba(0,0,0,0.2)]"
          >

            <div className="mb-5 flex items-center gap-2">

              <Search className="h-5 w-5 text-cyan-400" />

              <h2 className="text-lg font-semibold">
                Threat Scanner
              </h2>

            </div>


            {/* INPUT TYPE */}

            <div className="mb-4 flex rounded-lg bg-[#030916] p-1">

              <button
                onClick={() => {
                  setInputType("url");
                  setInput("");
                  setResult(null);
                  setError("");
                }}
                className={`flex flex-1 items-center justify-center gap-2 rounded-md px-4 py-3 text-sm transition ${
                  inputType === "url"
                    ? "bg-cyan-500 text-slate-950 shadow-[0_0_15px_rgba(34,211,238,0.25)]"
                    : "text-slate-500 hover:text-slate-200"
                }`}
              >
                <Link className="h-4 w-4" />
                URL Analysis
              </button>


              <button
                onClick={() => {
                  setInputType("email");
                  setInput("");
                  setResult(null);
                  setError("");
                }}
                className={`flex flex-1 items-center justify-center gap-2 rounded-md px-4 py-3 text-sm transition ${
                  inputType === "email"
                    ? "bg-cyan-500 text-slate-950 shadow-[0_0_15px_rgba(34,211,238,0.25)]"
                    : "text-slate-500 hover:text-slate-200"
                }`}
              >
                <Mail className="h-4 w-4" />
                Email Analysis
              </button>

            </div>


            {/* INPUT */}

            {inputType === "url" ? (

              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    analyzeInput();
                  }
                }}
                placeholder="Enter URL to analyze (e.g., https://suspicious-site.com)"
                className="mb-4 w-full rounded-lg border border-slate-700 bg-[#030916] px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400"
              />

            ) : (

              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Paste email content to analyze..."
                rows={5}
                className="mb-4 w-full resize-none rounded-lg border border-slate-700 bg-[#030916] px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400"
              />

            )}


            {/* ERROR */}

            {error && (
              <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 shrink-0" />
                  {error}
                </div>
              </div>
            )}


            {/* ANALYZE BUTTON */}

            <button
              onClick={analyzeInput}
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-500 px-5 py-3 font-semibold text-slate-950 transition hover:from-cyan-400 hover:to-blue-400 disabled:cursor-not-allowed disabled:opacity-60"
            >

              {loading ? (
                <>
                  <Activity className="h-4 w-4 animate-spin" />
                  Running Detection Pipeline...
                </>
              ) : (
                <>
                  <Zap className="h-4 w-4" />
                  Run Detection Pipeline
                </>
              )}

            </button>


            {/* QUICK TESTS */}

            {inputType === "url" && (

              <div className="mt-5">

                <p className="mb-3 text-xs text-slate-500">
                  Quick test samples:
                </p>

                <div className="flex flex-wrap gap-2">

                  <SampleButton
                    text="Obvious Phishing"
                    onClick={() =>
                      useSample("http://verify-paypal-login.xyz")
                    }
                  />

                  <SampleButton
                    text="URL Shortener"
                    onClick={() =>
                      useSample("https://bit.ly/secure-login")
                    }
                  />

                  <SampleButton
                    text="IP-Based URL"
                    onClick={() =>
                      useSample("http://192.168.1.25/login")
                    }
                  />

                  <SampleButton
                    text="Legitimate-Looking"
                    onClick={() =>
                      useSample("https://chatgpt.com")
                    }
                  />

                  <SampleButton
                    text="Subtle Phishing"
                    onClick={() =>
                      useSample("http://verify-paypa1-login.com")
                    }
                  />

                </div>

              </div>

            )}

          </motion.div>


          {/* ================= RESULTS PANEL ================= */}

          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="min-h-[480px] rounded-xl border border-slate-800 bg-[#050d1b] p-5"
          >

            {!result ? (

              <div className="flex h-full min-h-[440px] items-center justify-center rounded-lg border border-slate-800/70 bg-[linear-gradient(rgba(20,40,65,0.2)_1px,transparent_1px),linear-gradient(90deg,rgba(20,40,65,0.2)_1px,transparent_1px)] bg-[size:28px_28px]">

                <div className="max-w-sm text-center">

                  <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-xl border border-slate-700 bg-slate-900/70">
                    <BarChart3 className="h-7 w-7 text-slate-600" />
                  </div>

                  <p className="text-sm text-slate-400">
                    Enter a URL or email content to begin analysis.
                  </p>

                  <p className="mt-1 text-xs text-slate-600">
                    Results will appear here.
                  </p>

                </div>

              </div>

            ) : (

              <AnalysisResultPanel
                result={result}
                riskIsHigh={riskIsHigh}
              />

            )}

          </motion.div>

        </section>


        {/* ================= ANALYTICS ================= */}

        <section className="mt-5 rounded-xl border border-slate-800 bg-[#071123] p-7">

          <div className="flex items-center justify-center gap-3 text-sm text-slate-500">

            <BarChart3 className="h-5 w-5 text-blue-400" />

            {totalScans === 0
              ? "Run some scans to see analytics here."
              : `${totalScans} scan${
                  totalScans === 1 ? "" : "s"
                } completed.`}

          </div>

        </section>

      </main>

    </div>
  );
}


/* ============================================================
   STAT CARD
============================================================ */

function StatCard({
  title,
  value,
  icon,
  border,
}: {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  border: "cyan" | "red" | "yellow" | "green";
}) {

  const styles = {
    cyan: {
      border: "border-cyan-500/40",
      text: "text-cyan-400",
      glow: "shadow-[0_0_20px_rgba(34,211,238,0.12)]",
    },
    red: {
      border: "border-red-500/40",
      text: "text-red-400",
      glow: "shadow-[0_0_20px_rgba(248,113,113,0.12)]",
    },
    yellow: {
      border: "border-yellow-500/40",
      text: "text-yellow-400",
      glow: "shadow-[0_0_20px_rgba(250,204,21,0.10)]",
    },
    green: {
      border: "border-emerald-500/40",
      text: "text-emerald-400",
      glow: "shadow-[0_0_20px_rgba(52,211,153,0.10)]",
    },
  };

  const style = styles[border];

  return (
    <div
      className={`rounded-xl border ${style.border} bg-[#071123] p-5 ${style.glow}`}
    >

      <div className="flex items-start justify-between">

        <div>

          <p className="text-[11px] font-medium tracking-wide text-slate-500">
            {title}
          </p>

          <p className="mt-3 text-2xl font-bold text-slate-100">
            {value}
          </p>

        </div>

        <div className={style.text}>
          {icon}
        </div>

      </div>

    </div>
  );
}


/* ============================================================
   SAMPLE BUTTON
============================================================ */

function SampleButton({
  text,
  onClick,
}: {
  text: string;
  onClick: () => void;
}) {

  return (
    <button
      onClick={onClick}
      className="rounded-full border border-slate-700 bg-slate-900/50 px-3 py-1.5 text-xs text-slate-400 transition hover:border-cyan-500/50 hover:text-cyan-300"
    >
      {text}
    </button>
  );
}


/* ============================================================
   RESULT PANEL
============================================================ */

function AnalysisResultPanel({
  result,
  riskIsHigh,
}: {
  result: AnalysisResult;
  riskIsHigh: boolean;
}) {

  const predictionIsPhishing = String(result.prediction)
    .toLowerCase()
    .includes("phishing");

  const riskScore = result.risk?.riskScore ?? result.confidence;

  return (

    <div className="space-y-4">


      {/* RESULT HEADER */}

      <div
        className={`rounded-xl border p-5 ${
          predictionIsPhishing
            ? "border-red-500/40 bg-red-500/5"
            : "border-emerald-500/40 bg-emerald-500/5"
        }`}
      >

        <div className="flex items-start justify-between gap-4">

          <div>

            <p className="text-[10px] uppercase tracking-widest text-slate-500">
              Analysis Result
            </p>

            <h3
              className={`mt-1 text-2xl font-bold ${
                predictionIsPhishing
                  ? "text-red-400"
                  : "text-emerald-400"
              }`}
            >
              {result.prediction}
            </h3>

            <p className="mt-1 max-w-[420px] truncate text-xs text-slate-500">
              {result.url || "Email analysis"}
            </p>

          </div>


          <div className="text-right">

            <p
              className={`text-3xl font-bold ${
                predictionIsPhishing
                  ? "text-red-400"
                  : "text-emerald-400"
              }`}
            >
              {result.confidence}%
            </p>

            <p className="text-[10px] text-slate-600">
              Confidence
            </p>

          </div>

        </div>

      </div>


      {/* MODEL CARDS */}

      {result.models && (

        <div className="grid grid-cols-3 gap-3">

          <MiniCard
            title="Random Forest"
            value={result.models.random_forest.prediction}
            secondary={`${result.models.random_forest.confidence}%`}
          />

          <MiniCard
            title="SVM"
            value={result.models.svm.prediction}
            secondary={`${result.models.svm.confidence}%`}
          />

          <MiniCard
            title="Model Agreement"
            value={result.agreement || "—"}
            secondary=""
          />

        </div>

      )}


      {/* RISK */}

      {result.risk && (

        <div className="rounded-xl border border-slate-800 bg-[#071123] p-4">

          <div className="flex items-start justify-between">

            <div>

              <p className="text-[10px] uppercase tracking-widest text-slate-500">
                Risk Analysis
              </p>

              <p
                className={`mt-1 font-semibold ${
                  riskIsHigh
                    ? "text-red-400"
                    : "text-emerald-400"
                }`}
              >
                {result.risk.riskLabel}
              </p>

              <p className="mt-2 text-xs leading-5 text-slate-500">
                {result.risk.summary}
              </p>

            </div>

            <div className="text-right">

              <p
                className={`text-3xl font-bold ${
                  riskIsHigh
                    ? "text-red-400"
                    : "text-emerald-400"
                }`}
              >
                {riskScore}
              </p>

              <p className="text-[10px] text-slate-600">
                Risk Score
              </p>

            </div>

          </div>


          <div className="mt-4 grid grid-cols-3 gap-2">

            <RiskMini
              title="Raw Probability"
              value={`${result.risk.rawProbability}%`}
            />

            <RiskMini
              title="Calibrated Probability"
              value={`${result.risk.calibratedProbability}%`}
            />

            <RiskMini
              title="Risk Level"
              value={result.risk.riskLevel.toUpperCase()}
            />

          </div>

        </div>

      )}


      {/* REASONS */}

      {result.reasons && result.reasons.length > 0 && (

        <div className="rounded-xl border border-slate-800 bg-[#071123] p-4">

          <div className="mb-3 flex items-center gap-2">

            <Search className="h-4 w-4 text-cyan-400" />

            <h3 className="text-sm font-semibold">
              Why was this detected?
            </h3>

          </div>

          <div className="space-y-2">

            {result.reasons.map((reason, index) => (

              <div
                key={index}
                className="rounded-lg border border-slate-800 bg-[#030916] px-3 py-2 text-xs text-slate-400"
              >
                <span className="mr-2 text-yellow-400">
                  ⚠
                </span>
                {reason}
              </div>

            ))}

          </div>

        </div>

      )}


      {/* THREAT FEATURES */}

      {result.risk?.detectedFeatures &&
        result.risk.detectedFeatures.length > 0 && (

          <div className="rounded-xl border border-slate-800 bg-[#071123] p-4">

            <div className="mb-3 flex items-center gap-2">

              <ShieldAlert className="h-4 w-4 text-pink-400" />

              <h3 className="text-sm font-semibold">
                Detected Threat Features
              </h3>

            </div>

            <div className="space-y-2">

              {result.risk.detectedFeatures.map(
                (feature, index) => (

                  <div
                    key={index}
                    className="rounded-lg border border-slate-800 bg-[#030916] p-3"
                  >

                    <div className="flex items-center justify-between">

                      <p className="text-xs font-semibold text-cyan-300">
                        {feature.name}
                      </p>

                      <p className="text-[10px] font-semibold text-red-400">
                        +{feature.score} risk
                      </p>

                    </div>

                    <p className="mt-1 text-[10px] leading-4 text-slate-500">
                      {feature.explanation}
                    </p>

                  </div>

                )
              )}

            </div>

          </div>

        )}

    </div>
  );
}


/* ============================================================
   MINI CARDS
============================================================ */

function MiniCard({
  title,
  value,
  secondary,
}: {
  title: string;
  value: string;
  secondary: string;
}) {

  return (
    <div className="rounded-lg border border-slate-800 bg-[#071123] p-3">

      <p className="text-[9px] uppercase tracking-wide text-slate-600">
        {title}
      </p>

      <p className="mt-2 text-xs font-semibold text-slate-200">
        {value}
      </p>

      {secondary && (
        <p className="mt-1 text-[10px] text-cyan-400">
          {secondary}
        </p>
      )}

    </div>
  );
}


function RiskMini({
  title,
  value,
}: {
  title: string;
  value: string;
}) {

  return (
    <div className="rounded-lg bg-[#030916] p-3">

      <p className="text-[9px] text-slate-600">
        {title}
      </p>

      <p className="mt-1 text-xs font-semibold text-slate-200">
        {value}
      </p>

    </div>
  );
}


export default App;