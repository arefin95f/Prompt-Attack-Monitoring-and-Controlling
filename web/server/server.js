const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

try {
    require('dotenv').config({ path: path.join(__dirname, '../../.env') });
} catch (_) {
    // dotenv optional; process.env still works if set by the shell
}

const app = express();
const PORT = Number(process.env.NODE_PORT || process.env.PORT || 3001);

// ============================================================
// API CONFIGURATION (from environment / .env — never hardcode keys)
// ============================================================

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';
const OPENROUTER_ENDPOINT = process.env.OPENROUTER_ENDPOINT || 'https://openrouter.ai/api/v1/chat/completions';
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'openai/gpt-4o-mini';

const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const GROQ_ENDPOINT = process.env.GROQ_ENDPOINT || 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.1-70b-versatile';

const PYTHON_API = process.env.PYTHON_API || 'http://localhost:8000';

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/**
 * Call OpenRouter API for AI response
 */
async function callOpenRouter(messages, temperature = 0.7, maxTokens = 2048) {
    try {
        const response = await axios.post(
            OPENROUTER_ENDPOINT,
            {
                model: OPENROUTER_MODEL,
                messages: messages,
                temperature: temperature,
                max_tokens: maxTokens,
                top_p: 0.95,
                stream: false
            },
            {
                headers: {
                    'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
                    'Content-Type': 'application/json',
                    'HTTP-Referer': 'http://localhost:3001',
                    'X-Title': 'SecureAI Chatbot'
                },
                timeout: 30000
            }
        );

        return {
            success: true,
            text: response.data.choices[0].message.content,
            usage: response.data.usage,
            model: response.data.model
        };
    } catch (error) {
        console.error('❌ OpenRouter Error:', error.response?.data || error.message);
        return {
            success: false,
            error: error.response?.data?.error?.message || error.message
        };
    }
}

/**
 * Call Groq API as fallback
 */
async function callGroq(messages, temperature = 0.7, maxTokens = 2048) {
    try {
        const response = await axios.post(
            GROQ_ENDPOINT,
            {
                model: GROQ_MODEL,
                messages: messages,
                temperature: temperature,
                max_tokens: maxTokens,
                top_p: 0.95,
                stream: false
            },
            {
                headers: {
                    'Authorization': `Bearer ${GROQ_API_KEY}`,
                    'Content-Type': 'application/json'
                },
                timeout: 30000
            }
        );

        return {
            success: true,
            text: response.data.choices[0].message.content,
            usage: response.data.usage,
            model: response.data.model
        };
    } catch (error) {
        console.error('❌ Groq Error:', error.response?.data || error.message);
        return {
            success: false,
            error: error.response?.data?.error?.message || error.message
        };
    }
}

/**
 * Get AI response with fallback (OpenRouter → Groq)
 */
async function getAIResponse(messages, prompt, history = []) {
    // Try OpenRouter first
    console.log(`🤖 Calling OpenRouter (${OPENROUTER_MODEL})...`);
    const openrouterResult = await callOpenRouter(messages);
    
    if (openrouterResult.success) {
        console.log('✅ OpenRouter response received');
        return openrouterResult;
    }
    
    console.log('⚠️ OpenRouter failed, falling back to Groq...');
    
    // Fallback to Groq
    const groqResult = await callGroq(messages);
    
    if (groqResult.success) {
        console.log('✅ Groq response received (fallback)');
        return groqResult;
    }
    
    return {
        success: false,
        error: 'All AI services failed'
    };
}

// ============================================================
// MAIN CHAT ENDPOINT
// ============================================================

app.post('/api/chat', async (req, res) => {
    const { prompt, history = [], safe_suggestion = null, is_followup = false } = req.body;

    if (!prompt) {
        return res.status(400).json({ error: 'Prompt is required' });
    }

    console.log(`\n📝 User: ${prompt}`);
    console.log(`   Is follow-up: ${is_followup}`);
    console.log(`   Safe suggestion: ${safe_suggestion || 'None'}`);

    try {
        // ============================================================
        // STEP 1: Check with Python API
        // ============================================================
        console.log('🔍 Checking with Python API...');
        
        const detectResponse = await axios.post(`${PYTHON_API}/detect-conversational`, {
            prompt: prompt,
            conversation_id: null,
            user_message: null
        }, {
            timeout: 30000
        });

        const data = detectResponse.data;
        console.log(`   Response type: ${data.type}`);
        console.log(`   Suggestion: ${data.suggestion || 'None'}`);

        // ============================================================
        // STEP 2: If malicious, block and show safe suggestion
        // ============================================================
        if (data.type === 'blocked') {
            console.log('⚠️ MALICIOUS PROMPT DETECTED!');
            
            const suggestion = (data.suggestion || "").trim();
            const humanResponse = (data.response && String(data.response).trim())
                ? data.response
                : (suggestion
                    ? suggestion
                    : "That request looks unsafe. Tell me what you actually want help with in plain words.");
            
            return res.json({
                type: 'blocked',
                is_malicious: true,
                risk_score: data.risk_score || 0.8,
                attack_type: data.attack_type || 'unknown',
                attack_display_name: data.attack_display_name || data.attack_type || 'unknown',
                response: humanResponse,
                suggestion: suggestion,
                explanation: data.explanation || '',
                alternatives: [],
                conversation_id: data.conversation_id,
                status: data.status || 'waiting_for_response',
                legitimate_intent: data.legitimate_intent || '',
                removed_risks: data.removed_risks || [],
                intent_confidence: data.intent_confidence,
                fidelity_score: data.fidelity_score,
                needs_clarification: Boolean(data.needs_clarification) || !suggestion,
                clarifying_question: data.clarifying_question || null,
                rewrite_source: data.rewrite_source || null,
                decision_source: data.decision_source || null,
                processing_time: data.processing_time || null,
                retrieval: data.retrieval || null,
                layer2b: data.layer2b || null,
                normalization: data.normalization || null
            });
        }

        // ============================================================
        // STEP 3: If follow-up, send to AI with context
        // ============================================================
        if (is_followup && safe_suggestion) {
            console.log('🔄 Follow-up: Sending to OpenRouter with context...');
            
            const messages = [
                {
                    role: 'system',
                    content: `You are a helpful AI assistant. The user's original request was flagged as potentially unsafe, and you suggested this safe alternative:

Safe alternative: "${safe_suggestion}"

The user responded with: "${prompt}"

Please respond naturally to the user's response. If they accepted the safe alternative, answer the safe alternative. If they rejected it, ask what they'd like to know instead. If they're confused, clarify. Be helpful and conversational.`
                },
                {
                    role: 'user',
                    content: prompt
                }
            ];

            const aiResult = await getAIResponse(messages, prompt, history);
            
            if (aiResult.success) {
                return res.json({
                    type: 'success',
                    is_malicious: false,
                    prompt: prompt,
                    response: aiResult.text,
                    is_followup: true,
                    provider: 'openrouter'
                });
            } else {
                return res.json({
                    type: 'success',
                    is_malicious: false,
                    prompt: prompt,
                    response: "I received your message. How can I help you?",
                    warning: 'AI service unavailable'
                });
            }
        }

        // ============================================================
        // STEP 4: If safe, forward to AI
        // ============================================================
        if (data.type === 'safe') {
            console.log('✅ Prompt is safe, sending to OpenRouter...');

            // Build messages with history
            const messages = [
                {
                    role: 'system',
                    content: 'You are a helpful AI assistant. Provide clear, accurate, and helpful responses.'
                }
            ];

            // Add conversation history
            for (const msg of history) {
                messages.push({
                    role: msg.role === 'user' ? 'user' : 'assistant',
                    content: msg.content
                });
            }

            // Add current prompt
            messages.push({
                role: 'user',
                content: prompt
            });

            const aiResult = await getAIResponse(messages, prompt, history);
            
            if (aiResult.success) {
                return res.json({
                    type: 'success',
                    is_malicious: false,
                    risk_score: data.risk_score || 0,
                    prompt: prompt,
                    response: aiResult.text,
                    provider: 'openrouter',
                    model: aiResult.model
                });
            } else {
                return res.json({
                    type: 'success',
                    is_malicious: false,
                    prompt: prompt,
                    response: "I received your message. How can I help you?",
                    warning: 'AI service temporarily unavailable'
                });
            }
        }

        // ============================================================
        // STEP 5: Fallback
        // ============================================================
        return res.json({
            type: 'success',
            is_malicious: false,
            prompt: prompt,
            response: "I received your message. How can I help you?"
        });

    } catch (error) {
        console.error('❌ Error:', error.message);
        if (error.response) {
            console.error('   Response data:', error.response.data);
        }
        
        // ============================================================
        // STEP 6: Fallback - Direct to AI if Python API is down
        // ============================================================
        if (error.code === 'ECONNREFUSED') {
            console.log('⚠️ Python API not running, forwarding directly to OpenRouter...');
            
            try {
                const messages = [
                    {
                        role: 'system',
                        content: 'You are a helpful AI assistant.'
                    },
                    {
                        role: 'user',
                        content: prompt
                    }
                ];

                const aiResult = await getAIResponse(messages, prompt, history);
                
                if (aiResult.success) {
                    return res.json({
                        type: 'success',
                        is_malicious: false,
                        prompt: prompt,
                        response: aiResult.text,
                        warning: 'Python API not available, using OpenRouter directly'
                    });
                }
            } catch (aiError) {
                return res.status(500).json({
                    error: 'Failed to get response from AI',
                    details: aiError.message
                });
            }
        }

        return res.status(500).json({
            error: 'Failed to process request',
            details: error.message
        });
    }
});

// ============================================================
// CONVERSATIONAL CONTINUATION
// ============================================================

app.post('/api/chat-conversational', async (req, res) => {
    const { prompt, conversation_id, user_message, safe_suggestion } = req.body;

    if (!prompt) {
        return res.status(400).json({ error: 'Prompt is required' });
    }

    console.log(`\n📝 Conversational: ${prompt}`);
    console.log(`   Safe suggestion: ${safe_suggestion || 'None'}`);

    try {
        const response = await axios.post(`${PYTHON_API}/detect-conversational`, {
            prompt: prompt,
            conversation_id: conversation_id,
            user_message: prompt,
            safe_suggestion: safe_suggestion || null
        }, {
            timeout: 30000
        });

        const data = response.data;
        console.log(`   Follow-up suggestion: ${data.suggestion || 'None'}`);

        if (data.type === 'blocked') {
            const suggestion = (data.suggestion || '').trim();
            const humanResponse = (data.response && String(data.response).trim())
                ? data.response
                : (suggestion
                    ? suggestion
                    : 'That request looks unsafe. Tell me what you actually want help with in plain words.');
            return res.json({
                type: 'blocked',
                is_malicious: true,
                response: humanResponse,
                suggestion: suggestion,
                explanation: data.explanation || '',
                alternatives: [],
                conversation_id: data.conversation_id || conversation_id,
                confirmed: false,
                attack_type: data.attack_type || 'unknown',
                attack_display_name: data.attack_display_name || data.attack_type || 'unknown',
                legitimate_intent: data.legitimate_intent || '',
                removed_risks: data.removed_risks || [],
                fidelity_score: data.fidelity_score,
                needs_clarification: Boolean(data.needs_clarification) || !suggestion,
                clarifying_question: data.clarifying_question || null,
                status: data.status || 'waiting_for_response'
            });
        }

        if (data.type === 'success') {
            const finalPrompt = data.final_prompt || data.suggestion || safe_suggestion || prompt;
            
            const messages = [
                {
                    role: 'system',
                    content: 'You are a helpful AI assistant.'
                },
                {
                    role: 'user',
                    content: finalPrompt
                }
            ];

            const aiResult = await getAIResponse(messages, finalPrompt, []);
            
            if (aiResult.success) {
                return res.json({
                    type: 'success',
                    is_malicious: false,
                    response: aiResult.text,
                    provider: 'openrouter'
                });
            } else {
                return res.json({
                    type: 'success',
                    is_malicious: false,
                    response: "I received your message. How can I help you?"
                });
            }
        }

        return res.json({
            type: 'success',
            is_malicious: false,
            response: "I received your message."
        });

    } catch (error) {
        console.error('❌ Error:', error.message);
        return res.json({
            type: 'success',
            is_malicious: false,
            response: "I received your message. How can I help you?"
        });
    }
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/api/health', async (req, res) => {
    try {
        const response = await axios.get(`${PYTHON_API}/health`);
        
        // Check OpenRouter API availability
        let openrouter_status = 'unknown';
        try {
            const testResponse = await axios.post(
                OPENROUTER_ENDPOINT,
                {
                    model: OPENROUTER_MODEL,
                    messages: [{ role: 'user', content: 'Hello' }],
                    max_tokens: 5
                },
                {
                    headers: {
                        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
                        'Content-Type': 'application/json',
                        'HTTP-Referer': 'http://localhost:3001',
                        'X-Title': 'SecureAI Chatbot'
                    },
                    timeout: 5000
                }
            );
            openrouter_status = testResponse.status === 200 ? 'available' : 'error';
        } catch (e) {
            openrouter_status = 'unavailable';
        }
        
        return res.json({
            status: 'healthy',
            pipeline_loaded: response.data.pipeline_loaded,
            openrouter_status: openrouter_status,
            groq_status: 'available' // Fallback
        });
    } catch (error) {
        return res.json({
            status: 'degraded',
            pipeline_loaded: false,
            openrouter_status: 'unavailable',
            groq_status: 'unknown'
        });
    }
});

// ============================================================
// START SERVER
// ============================================================

app.listen(PORT, () => {
    console.log('='.repeat(60));
    console.log('🚀 AI CHATBOT DASHBOARD');
    console.log('='.repeat(60));
    console.log(`📡 Server: http://localhost:${PORT}`);
    console.log(`🔗 Python API: ${PYTHON_API}`);
    console.log(`🤖 OpenRouter Model: ${OPENROUTER_MODEL}`);
    console.log(`🔑 OpenRouter API Key: ${OPENROUTER_API_KEY ? '✅ Set' : '❌ Missing'}`);
    console.log(`🔄 Fallback: Groq (${GROQ_MODEL})`);
    console.log('='.repeat(60));
    console.log('\n⚠️ Make sure Python API is running: python run_api.py');
    console.log('='.repeat(60));
});