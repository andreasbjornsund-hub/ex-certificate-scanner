/**
 * Ex Certificate Parser
 * Extracts structured data from IECEx, ATEX, and UKCA certificate PDFs.
 * Runs entirely client-side — no data leaves the browser.
 */

const ExParser = (() => {
    // Known notified bodies / certification bodies
    const CERT_BODIES = [
        'BASEEFA', 'SIRA', 'DEKRA', 'PTB', 'INERIS', 'CESI', 'LCIE',
        'UL', 'FM', 'CSA Group', 'CSA', 'TÜV', 'TUV', 'SGS', 'ZELM', 'FTZU',
        'NEMKO', 'DEMKO', 'KEMA', 'BVS', 'IBExU', 'CERCHAR',
        'SIMTARS', 'MSHA', 'ITS', 'Intertek', 'Bureau Veritas',
        'CML', 'Eurofins', 'Presafe', 'Fiditas', 'FIDITAS',
        'ExVeritas', 'SGS-CSTC', 'CQM', 'PCEC', 'NEPSI', 'TIIS',
        'KOSHA', 'KTL', 'PESO', 'CCOE', 'DNV GL', 'DNV',
        'EXAM', 'Element', 'TestSafe',
        'Physikalisch-Technische Bundesanstalt'
    ];

    const PROTECTION_TYPES = {
        'd': 'Flameproof enclosure',
        'e': 'Increased safety',
        'i': 'Intrinsic safety',
        'p': 'Pressurized enclosure',
        'o': 'Oil immersion',
        'q': 'Powder/sand filling',
        'n': 'Non-sparking',
        'm': 'Encapsulation',
        't': 'Protection by enclosure',
        's': 'Special protection',
        'op': 'Optical radiation',
        'h': 'Non-incendive'
    };

    const GAS_GROUP_INFO = {
        'IIC': 'Hydrogen, acetylene (most stringent)',
        'IIB': 'Ethylene',
        'IIA': 'Propane (least stringent)',
        'I': 'Mining (methane)',
        'IIIA': 'Combustible flyings',
        'IIIB': 'Non-conductive dust',
        'IIIC': 'Conductive dust (most stringent)'
    };

    const TEMP_CLASS_INFO = {
        'T1': '450°C', 'T2': '300°C', 'T3': '200°C',
        'T4': '135°C', 'T5': '100°C', 'T6': '85°C'
    };

    const VALID_PROT_CODES = new Set([
        'd','da','db','dc','e','ea','eb','ec','i','ia','ib','ic',
        'p','pa','pb','pc','px','py','pz','o','ob','oc','q','qa','qb',
        'n','na','nc','nr','nl','m','ma','mb','mc',
        't','ta','tb','tc','s','h','op'
    ]);

    function parse(text) {
        const result = {
            certNumber: null,
            certType: null,
            marking: null,
            markings: [],
            protectionTypes: [],
            gasGroup: null,
            gasGroupInfo: null,
            tempClass: null,
            tempClassMax: null,
            epl: null,
            zone: null,
            ipRating: null,
            ambientTemp: null,
            manufacturer: null,
            equipment: null,
            notifiedBody: null,
            issueDate: null,
            expiryDate: null,
            specialConditions: null,
            standard: null,
            category: null,
            group: null,
            raw: text
        };

        const t = text;

        // --- Certificate Number ---

        // IECEx: IECEx XXX 12.0001X or IECEx XXX 12.0001X/1.0
        const iecex = t.match(/IECEx\s+[A-Z]{2,5}\s+\d{2}\.\d{3,5}[A-Z]?(?:\/\d+\.\d+)?/i);
        if (iecex) {
            result.certNumber = iecex[0].replace(/\s+/g, ' ').trim();
            result.certType = 'IECEx';
        }

        // ATEX: TRAC13ATEX0009X, FIDI 24 ATEX 0075X/1, BASEEFA15ATEX0123X
        if (!result.certNumber) {
            const atex = t.match(/[A-Z]{2,10}\s*\d{2}\s*ATEX\s*\d{3,5}\s*[XU]?(?:\s*\/\s*V?\d[\w]*)?/i);
            if (atex) {
                result.certNumber = atex[0].replace(/\s+/g, '').trim();
                result.certType = 'ATEX';
            }
        }

        // UKCA
        if (!result.certNumber) {
            const ukca = t.match(/UKCA\s+[A-Z0-9\-.\/]+/i);
            if (ukca) {
                result.certNumber = ukca[0].trim();
                result.certType = 'UKCA';
            }
        }

        // Detect dual certification
        if (result.certType === 'IECEx') {
            const atexAlso = t.match(/\d{2}\s*ATEX\s*\d{3,5}/i);
            if (atexAlso) result.certType = 'IECEx + ATEX';
        }

        // --- Full Ex Marking ---
        // Collect ALL markings; prefer most complete
        const markingPatterns = [
            // Full with temp+EPL: Ex db IIC T4 Gb, Ex db ib [ib] IIB T4 Gb
            /\bEx\s+(?:[deimopqstnabrh]{1,4}\s+)+(?:\[[a-z]{1,4}\]\s+)?I{1,3}[ABC]*(?:\+H2)?\s+T[1-6](?:\/T[1-6])*\s*[GDM][abc](?:\/[GDM][abc])*/gi,
            // Mining: Ex ia I Ma
            /\bEx\s+(?:[deimopqstnabrh]{1,4}\s+)+I\s+M[ab]/gi,
            // Dust with absolute temp: Ex tb IIIC T135°C Db
            /\bEx\s+(?:[deimopqstnabrh]{1,4}\s+)+I{2,3}[ABC]*\s+T\d+°?\s*C\s*[GDM][abc]/gi,
            // With temp class, no EPL
            /\bEx\s+(?:[deimopqstnabrh]{1,4}\s+)+(?:\[[a-z]{1,4}\]\s+)?I{1,3}[ABC]*(?:\+H2)?\s+T[1-6](?:\/T[1-6])*/gi,
            // Minimal: Ex [types] [group]
            /\bEx\s+(?:[deimopqstnabrh]{1,4}\s+)+I{1,3}[ABC]*/gi,
        ];

        const allMarkings = [];
        const seenMarkings = new Set();
        for (const pat of markingPatterns) {
            const matches = t.match(pat);
            if (matches) {
                for (const m of matches) {
                    const cleaned = m.trim().replace(/\s+/g, ' ');
                    if (!seenMarkings.has(cleaned)) {
                        seenMarkings.add(cleaned);
                        allMarkings.push(cleaned);
                    }
                }
            }
        }

        if (allMarkings.length > 0) {
            // Primary = longest (most complete)
            allMarkings.sort((a, b) => b.length - a.length);
            result.marking = allMarkings[0];
            result.markings = allMarkings;
        }

        // --- Protection Types ---
        const markingSrc = result.marking || '';
        const protMatch = markingSrc.match(/^Ex\s+(.*?)(?:\[.*?\]\s*)?(?=I{1,3})/i);
        if (protMatch) {
            const raw = protMatch[1].trim();
            const codes = raw.split(/\s+/).filter(c => {
                const cl = c.toLowerCase();
                return VALID_PROT_CODES.has(cl) || VALID_PROT_CODES.has(cl.replace(/[abc]$/, ''));
            });
            result.protectionTypes = codes.map(code => {
                const cl = code.toLowerCase();
                const baseCode = cl.replace(/[abcrs]$/, '');
                const level = cl.match(/[abc]$/)?.[0] || null;
                return {
                    code: code,
                    baseType: baseCode,
                    level: level,
                    description: PROTECTION_TYPES[baseCode] || PROTECTION_TYPES[cl] || 'Unknown'
                };
            });
        }

        // --- Gas Group ---
        const gasFromMarking = markingSrc.match(/\b(III[ABC]|II[ABC](?:\+H2)?)\b/);
        const gasFromText = t.match(/\b(III[ABC]|II[ABC](?:\+H2)?|Group\s+I(?:I[ABC]?)?)\b/);
        const gasMatch = gasFromMarking || gasFromText;
        if (gasMatch) {
            let group = gasMatch[1].replace(/^Group\s+/i, '');
            result.gasGroup = group;
            result.gasGroupInfo = GAS_GROUP_INFO[group] || null;
        }

        // --- Temperature Class ---
        const tempFromMarking = markingSrc.match(/\bT([1-6])\b/);
        const tempFromText = t.match(/\bT([1-6])\b/);
        const tempMatch = tempFromMarking || tempFromText;
        if (tempMatch) {
            result.tempClass = 'T' + tempMatch[1];
            result.tempClassMax = TEMP_CLASS_INFO['T' + tempMatch[1]] || null;
        }

        // --- Equipment Protection Level ---
        const eplFromMarking = markingSrc.match(/\b([GDM][abc])\b/);
        const eplFromText = t.match(/\b([GDM][abc])\b/);
        const eplMatch = eplFromMarking || eplFromText;
        if (eplMatch) {
            result.epl = eplMatch[1];
        }

        // --- Zone ---
        const zoneMatch = t.match(/Zone\s+(\d{1,2})/i);
        if (zoneMatch) {
            result.zone = 'Zone ' + zoneMatch[1];
        } else if (result.epl) {
            const eplZoneMap = { 'Ga':'0','Gb':'1','Gc':'2','Da':'20','Db':'21','Dc':'22','Ma':'M1','Mb':'M2' };
            const derived = eplZoneMap[result.epl];
            if (derived) result.zone = 'Zone ' + derived + ' (derived from EPL)';
        }

        // --- IP Rating ---
        const ipMatch = t.match(/\bIP\s*([0-9X]{2}[A-Z]?)\b/i);
        if (ipMatch) {
            result.ipRating = 'IP' + ipMatch[1];
        }

        // --- Ambient Temperature ---
        const ambMatch = t.match(/(-\d+)\s*°?\s*C?\s*(to|\.{2,3}|–|—|-)\s*\+?(\d+)\s*°?\s*C/i);
        if (ambMatch) {
            result.ambientTemp = `${ambMatch[1]}°C to +${ambMatch[3]}°C`;
        }

        // --- Manufacturer ---
        const mfrPatterns = [
            /Manufacturer[:\s]*\n\s*Address[:\s]*\n\s*([^\n]{3,80})/i,
            /Manufacturer[:\s]*\n\s*([^\n]{3,80})/i,
            /Manufacturer[:\s]+([^\n]{3,80})/i,
            /Applicant[:\s]*\n\s*([^\n]{3,80})/i,
            /Applicant[:\s]+([^\n]{3,80})/i,
            /Issued\s+to[:\s]*\n\s*([^\n]{3,80})/i,
            /Issued\s+to[:\s]+([^\n]{3,80})/i,
        ];
        for (const pat of mfrPatterns) {
            const m = t.match(pat);
            if (m) {
                let val = m[1].trim().replace(/[,\s]+$/, '');
                if (/^(Address|Name|Location|see\b|refer\b|as\s)/i.test(val)) continue;
                if (val.length < 3) continue;
                result.manufacturer = val;
                break;
            }
        }

        // --- Equipment / Product Name ---
        const eqPatterns = [
            /Equipment[:\s]*\n\s*(?!Group)([^\n]{3,120})/i,
            /Equipment[:\s]+(?!Group)([^\n]{3,120})/i,
            /Apparatus[:\s]+([^\n]{3,120})/i,
            /Type\s+of\s+Equipment[:\s]+([^\n]{3,120})/i,
            /Product[:\s]*\n\s*([^\n]{3,120})/i,
            /Product[:\s]+([^\n]{3,120})/i,
        ];
        for (const pat of eqPatterns) {
            const m = t.match(pat);
            if (m) {
                let val = m[1].trim().replace(/[,\s]+$/, '');
                if (/^(or\s+Protective|Intended\s+for|listed\s+in)/i.test(val)) continue;
                if (val.length < 3) continue;
                result.equipment = val;
                break;
            }
        }

        // --- Notified Body ---
        const sortedBodies = [...CERT_BODIES].sort((a, b) => b.length - a.length);
        for (const body of sortedBodies) {
            if (t.includes(body)) {
                result.notifiedBody = body;
                break;
            }
        }

        // --- Dates ---
        const issuePats = [
            /Date\s+of\s+Issue[:\s]*\n?\s*(\d{4}[-/]\d{2}[-/]\d{2})/i,
            /Date\s+of\s+Issue[:\s]+(\d{1,2}[\s./-]\w{3,9}[\s./-]\d{4})/i,
            /Issue\s*(?:d|Date)[:\s]+(\d{4}[-/]\d{2}[-/]\d{2})/i,
            /Issue\s*(?:d|Date)[:\s]+(\d{1,2}[\s./-]\w{3,9}[\s./-]\d{4})/i,
            /Issued[:\s]+(\d{1,2}[\s./-]\w{3,9}[\s./-]\d{4})/i,
        ];
        for (const pat of issuePats) {
            const m = t.match(pat);
            if (m) { result.issueDate = m[1].trim(); break; }
        }

        const expiryPats = [
            /Expir[ey]\s*(?:Date)?[:\s]+(\d{4}[-/]\d{2}[-/]\d{2})/i,
            /Expir[ey]\s*(?:Date)?[:\s]+(\d{1,2}[\s./-]\w{3,9}[\s./-]\d{4})/i,
            /Valid\s+(?:until|to)[:\s]+(\d{4}[-/]\d{2}[-/]\d{2})/i,
            /Valid\s+(?:until|to)[:\s]+(\d{1,2}[\s./-]\w{3,9}[\s./-]\d{4})/i,
            /Validity[:\s]+(\d{1,2}[\s./-]\w{3,9}[\s./-]\d{4})/i,
        ];
        for (const pat of expiryPats) {
            const m = t.match(pat);
            if (m) { result.expiryDate = m[1].trim(); break; }
        }

        // --- Special Conditions ---
        const specMatch = t.match(/Special\s+[Cc]onditions?\s*(?:for\s+(?:safe\s+)?use)?[:\s]+([\s\S]{10,500}?)(?=\n\s*\n|\n[A-Z]{2,}|\n\d+\.\s|$)/i);
        if (specMatch) {
            result.specialConditions = specMatch[1].trim().substring(0, 500);
        }

        // --- Standards ---
        const stdMatches = t.match(/(?:EN\s+)?(?:IEC\s*)?60079-\d+(?::\d{4})?(?:\+A\d+:\d{4})*/gi);
        if (stdMatches) {
            result.standard = [...new Set(stdMatches.map(s => s.trim()))].join(', ');
        }

        // --- ATEX Category ---
        const catMatch = t.match(/\bII\s+([1-3])\s+[GDM]\b/) || t.match(/\bCategory\s+([1-3][GDM]?)\b/i);
        if (catMatch) {
            result.category = catMatch[1];
        }

        // --- Equipment Group ---
        const grpMatch = t.match(/Equipment\s+[Gg]roup\s+(I{1,3})/);
        if (grpMatch) {
            result.group = grpMatch[1];
        } else {
            const grpAlt = t.match(/\b(I{2,3})\s+[1-3]\s+[GDM]\b/);
            if (grpAlt) result.group = grpAlt[1];
        }

        return result;
    }

    function confidence(result) {
        let score = 0;
        const weights = {
            certNumber: 20,
            marking: 20,
            gasGroup: 10,
            tempClass: 10,
            protectionTypes: 10,
            epl: 5,
            manufacturer: 5,
            equipment: 5,
            notifiedBody: 5,
            ipRating: 3,
            ambientTemp: 3,
            issueDate: 2,
            expiryDate: 2
        };

        for (const [field, weight] of Object.entries(weights)) {
            const val = result[field];
            if (val && (Array.isArray(val) ? val.length > 0 : true)) {
                score += weight;
            }
        }
        return Math.min(100, score);
    }

    return { parse, confidence, PROTECTION_TYPES, GAS_GROUP_INFO, TEMP_CLASS_INFO };
})();
