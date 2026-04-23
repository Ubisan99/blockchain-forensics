#!/usr/bin/env python3
"""
AI-Powered Investigation Module using LangChain
Provides natural language interface for blockchain forensics
"""

import os
import json
from typing import Dict, List, Optional, Any
from datetime import datetime

# Try to import LangChain
try:
    from langchain.llms import OpenAI, HuggingFaceHub
    from langchain.chains import LLMChain, ConversationalRetrievalChain
    from langchain.prompts import PromptTemplate
    from langchain.memory import ConversationBufferMemory
    from langchain.vectorstores import FAISS
    from langchain.embeddings import OpenAIEmbeddings, HuggingFaceEmbeddings
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain.docstore.document import Document
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("Warning: LangChain not available. Using basic NLP fallback.")


class BlockchainInvestigationAI:
    """
    AI-powered investigation assistant using LangChain
    Helps forensic analysts investigate blockchain transactions
    """
    
    def __init__(self, model_name: str = "gpt-3.5-turbo", openai_api_key: str = ""):
        self.model_name = model_name
        self.llm = None
        self.chain = None
        self.memory = None
        self.investigation_context = []
        
        if LANGCHAIN_AVAILABLE:
            self.setup_llm(openai_api_key)
    
    def setup_llm(self, api_key: str = ""):
        """Setup the language model"""
        if not LANGCHAIN_AVAILABLE:
            return
        
        # Use OpenAI if API key provided, otherwise use HuggingFace
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key
            self.llm = OpenAI(model_name=self.model_name, temperature=0.1)
        else:
            # Try HuggingFace as fallback
            try:
                self.llm = HuggingFaceHub(
                    repo_id="google/flan-t5-base",
                    model_kwargs={"temperature": 0.1, "max_length": 512}
                )
            except:
                print("Warning: Could not initialize LLM")
                return
        
        # Setup memory for conversation
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            output_key="answer"
        )
        
        # Create investigation prompt
        self.create_investigation_chain()
    
    def create_investigation_chain(self):
        """Create the investigation prompt chain"""
        if not self.llm:
            return
        
        investigation_template = """You are a blockchain forensics expert assistant. 
Your role is to help analyze blockchain transactions, detect patterns, and identify potential legal violations.

Context about the current investigation:
{context}

Previous conversation:
{chat_history}

User question: {question}

Provide a detailed, accurate response based on:
1. Transaction patterns detected
2. Risk factors identified  
3. Legal frameworks that may apply
4. Recommendations for further investigation

If you need more specific data to answer accurately, state what additional information would be helpful.

Response:"""

        prompt = PromptTemplate(
            template=investigation_template,
            input_variables=["context", "chat_history", "question"]
        )
        
        self.chain = LLMChain(
            llm=self.llm,
            prompt=prompt,
            memory=self.memory,
            verbose=True
        )
    
    def add_investigation_context(self, data: Dict):
        """Add investigation context (transactions, address data, etc.)"""
        context_str = self.format_context(data)
        self.investigation_context.append({
            "timestamp": datetime.now().isoformat(),
            "data": data,
            "summary": context_str[:500]  # Keep summary for context
        })
        
        # Keep only last 10 context entries
        if len(self.investigation_context) > 10:
            self.investigation_context = self.investigation_context[-10:]
    
    def format_context(self, data: Dict) -> str:
        """Format data for context"""
        lines = []
        
        if "address" in data:
            lines.append(f"Address: {data['address']}")
        
        if "transactions" in data:
            lines.append(f"Transactions analyzed: {len(data['transactions'])}")
        
        if "risk_score" in data:
            lines.append(f"Risk score: {data['risk_score']}")
        
        if "patterns" in data:
            lines.append(f"Patterns detected: {', '.join(data['patterns'])}")
        
        if "violations" in data:
            lines.append(f"Violations found: {len(data['violations'])}")
            for v in data["violations"][:3]:  # First 3
                lines.append(f"  - {v.get('type', 'Unknown')}: {v.get('description', '')}")
        
        return "\n".join(lines)
    
    def ask(self, question: str) -> str:
        """
        Ask a question about the current investigation
        Returns AI-generated response
        """
        if not self.chain:
            return self.fallback_answer(question)
        
        # Build context from investigation data
        context = "\n\n".join([c["summary"] for c in self.investigation_context])
        
        try:
            response = self.chain.run(
                context=context,
                question=question
            )
            return response
        except Exception as e:
            print(f"Error in AI chain: {e}")
            return self.fallback_answer(question)
    
    def fallback_answer(self, question: str) -> str:
        """Fallback answer when LLM not available"""
        return f"""AI analysis not available. 

To get analysis, please ensure:
1. LangChain is installed: pip install langchain
2. OpenAI API key is provided, OR
3. HuggingFace is accessible

Question asked: {question}

Manual analysis required based on investigation data:
- Review transaction patterns
- Check risk scores
- Verify against legal frameworks"""


class EvidenceCollector:
    """
    Collects and organizes evidence for forensic investigation
    Uses LangChain for intelligent evidence correlation
    """
    
    def __init__(self):
        self.evidence: List[Dict] = []
        self.documents: List[Document] = []
        
        if LANGCHAIN_AVAILABLE:
            self.setup_vector_store()
    
    def setup_vector_store(self):
        """Setup vector store for evidence retrieval"""
        try:
            # Try OpenAI embeddings first
            try:
                self.embeddings = OpenAIEmbeddings()
            except:
                # Fallback to HuggingFace
                self.embeddings = HuggingFaceEmbeddings(
                    model_name="sentence-transformers/all-MiniLM-L6-v2"
                )
            
            self.vector_store = None
        except Exception as e:
            print(f"Warning: Could not setup vector store: {e}")
            self.embeddings = None
    
    def add_evidence(self, evidence: Dict):
        """Add evidence to the collection"""
        evidence_entry = {
            "id": len(self.evidence) + 1,
            "timestamp": datetime.now().isoformat(),
            "data": evidence,
            "type": evidence.get("type", "unknown"),
            "severity": evidence.get("severity", "unknown")
        }
        
        self.evidence.append(evidence_entry)
        
        # Create document for vector store
        if LANGCHAIN_AVAILABLE and self.embeddings:
            doc_text = self.format_evidence_text(evidence)
            doc = Document(
                page_content=doc_text,
                metadata={
                    "evidence_id": evidence_entry["id"],
                    "type": evidence_entry["type"],
                    "severity": evidence_entry["severity"]
                }
            )
            self.documents.append(doc)
            
            # Update vector store
            self.update_vector_store()
    
    def format_evidence_text(self, evidence: Dict) -> str:
        """Format evidence as searchable text"""
        parts = []
        
        if "address" in evidence:
            parts.append(f"Address: {evidence['address']}")
        
        if "transaction_hash" in evidence:
            parts.append(f"Transaction: {evidence['transaction_hash']}")
        
        if "pattern_type" in evidence:
            parts.append(f"Pattern detected: {evidence['pattern_type']}")
        
        if "description" in evidence:
            parts.append(f"Description: {evidence['description']}")
        
        if "legal_reference" in evidence:
            parts.append(f"Legal reference: {evidence['legal_reference']}")
        
        return " | ".join(parts)
    
    def update_vector_store(self):
        """Update the vector store with new evidence"""
        if not self.documents or not self.embeddings:
            return
        
        try:
            if self.vector_store:
                # Add to existing store
                self.vector_store.add_documents(self.documents[-1:])
            else:
                # Create new store
                text_splitter = RecursiveCharacterTextSplitter(
                    chunk_size=500,
                    chunk_overlap=50
                )
                splits = text_splitter.split_documents(self.documents)
                self.vector_store = FAISS.from_documents(splits, self.embeddings)
        except Exception as e:
            print(f"Warning: Could not update vector store: {e}")
    
    def search_evidence(self, query: str, top_k: int = 5) -> List[Dict]:
        """
        Search evidence using semantic similarity
        """
        if not self.vector_store:
            # Fallback to simple search
            return self.simple_search(query, top_k)
        
        try:
            docs = self.vector_store.similarity_search(query, k=top_k)
            results = []
            
            for doc in docs:
                evidence_id = doc.metadata.get("evidence_id")
                for e in self.evidence:
                    if e["id"] == evidence_id:
                        results.append(e)
                        break
            
            return results
        except Exception as e:
            print(f"Search error: {e}")
            return self.simple_search(query, top_k)
    
    def simple_search(self, query: str, top_k: int = 5) -> List[Dict]:
        """Simple keyword-based search fallback"""
        query_lower = query.lower()
        results = []
        
        for e in self.evidence:
            text = json.dumps(e["data"]).lower()
            if query_lower in text:
                results.append(e)
            
            if len(results) >= top_k:
                break
        
        return results
    
    def generate_investigation_report(self) -> str:
        """Generate a comprehensive investigation report"""
        report = []
        
        report.append("=" * 60)
        report.append("BLOCKCHAIN FORENSICS INVESTIGATION REPORT")
        report.append("=" * 60)
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append(f"Total evidence collected: {len(self.evidence)}")
        report.append("")
        
        # Group by severity
        by_severity = {}
        for e in self.evidence:
            sev = e.get("severity", "unknown")
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(e)
        
        # Report by severity
        for severity in ["critical", "high", "medium", "low"]:
            if severity in by_severity:
                report.append(f"\n{severity.upper()} SEVERITY EVIDENCE:")
                report.append("-" * 40)
                
                for e in by_severity[severity]:
                    report.append(f"\nEvidence ID: {e['id']}")
                    report.append(f"Type: {e.get('type', 'N/A')}")
                    report.append(f"Timestamp: {e.get('timestamp', 'N/A')}")
                    
                    data = e.get("data", {})
                    if "address" in data:
                        report.append(f"Address: {data['address']}")
                    if "pattern_type" in data:
                        report.append(f"Pattern: {data['pattern_type']}")
                    if "description" in data:
                        report.append(f"Description: {data['description']}")
        
        report.append("\n" + "=" * 60)
        report.append("END OF REPORT")
        report.append("=" * 60)
        
        return "\n".join(report)


class InvestigationAssistant:
    """
    Main investigation assistant combining all AI capabilities
    """
    
    def __init__(self, openai_api_key: str = ""):
        self.ai = BlockchainInvestigationAI(openai_api_key=openai_api_key)
        self.evidence = EvidenceCollector()
        self.case_data = {}
    
    def start_investigation(self, case_id: str, description: str):
        """Start a new investigation case"""
        self.case_data = {
            "case_id": case_id,
            "description": description,
            "started_at": datetime.now().isoformat(),
            "status": "active"
        }
        print(f"Investigation started: {case_id}")
        print(f"Description: {description}")
    
    def add_transaction_analysis(self, analysis_result: Dict):
        """Add transaction analysis results to investigation"""
        # Add to AI context
        self.ai.add_investigation_context(analysis_result)
        
        # Collect evidence
        if analysis_result.get("risk_score", 0) > 0.5:
            self.evidence.add_evidence({
                "type": "transaction_analysis",
                "severity": "high" if analysis_result.get("risk_score", 0) > 0.7 else "medium",
                "address": analysis_result.get("address"),
                "risk_score": analysis_result.get("risk_score"),
                "patterns": analysis_result.get("patterns_detected", []),
                "description": f"Risk score: {analysis_result.get('risk_score')}"
            })
    
    def add_violation_evidence(self, violation: Dict):
        """Add violation evidence"""
        severity = violation.get("severity", "medium").lower()
        
        self.evidence.add_evidence({
            "type": "legal_violation",
            "severity": severity,
            "violation_type": violation.get("type"),
            "description": violation.get("description"),
            "legal_reference": violation.get("legal_reference"),
            "address": violation.get("address")
        })
    
    def ask_investigator(self, question: str) -> str:
        """Ask the AI investigator a question"""
        return self.ai.ask(question)
    
    def get_evidence_report(self) -> str:
        """Generate evidence report"""
        return self.evidence.generate_investigation_report()
    
    def export_case(self, filepath: str):
        """Export case data to file"""
        export_data = {
            "case": self.case_data,
            "evidence_count": len(self.evidence.evidence),
            "evidence": self.evidence.evidence,
            "exported_at": datetime.now().isoformat()
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print(f"Case exported to: {filepath}")


if __name__ == "__main__":
    # Example usage
    assistant = InvestigationAssistant()
    
    # Start investigation
    assistant.start_investigation(
        case_id="CASE-2024-001",
        description="Investigation of suspected money laundering activity"
    )
    
    # Add analysis results
    test_analysis = {
        "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f4f2E1",
        "risk_score": 0.75,
        "patterns_detected": ["rapid_layering", "large_value_transfer"],
        "transactions_analyzed": 50
    }
    assistant.add_transaction_analysis(test_analysis)
    
    # Add violation
    test_violation = {
        "type": "money_laundering_suspicion",
        "severity": "HIGH",
        "description": "Multiple large transactions detected",
        "legal_reference": "Bank Secrecy Act"
    }
    assistant.add_violation_evidence(test_violation)
    
    # Ask question
    response = assistant.ask_investigator("What patterns have been detected in this investigation?")
    print("\nAI Response:")
    print(response)
    
    # Generate report
    print("\n" + assistant.get_evidence_report())
