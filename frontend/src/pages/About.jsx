export default function About() {
  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">About ScamShield</h1>
        <p className="text-slate-400">
          ScamShield is an AI-powered Digital Fraud Investigation and Intelligence Platform.
        </p>
      </div>
      <div className="card">
        <h3 className="font-semibold text-white mb-2">Our Approach</h3>
        <ul className="list-disc list-inside text-sm text-slate-300 space-y-2">
          <li>Hybrid AI: local ML (scikit-learn, Sentence Transformers, EasyOCR) + OpenAI for explanations.</li>
          <li>Explainable risk scoring calculated by the backend, not invented by the LLM.</li>
          <li>Every finding references actual evidence.</li>
          <li>No hardcoded API keys; unavailable services degrade to labelled fallbacks.</li>
        </ul>
      </div>
    </div>
  )
}